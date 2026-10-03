//! In-memory `EventStore` for tests and single-process use.
//!
//! Fork is copy-on-write: a child stores only its own events.
//! Reading from a forked child transparently stitches parent `0..fork_seq` + child events.
//! Multi-level fork chains are supported: a child of a child walks the chain recursively.

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use pos_core::{
    clock::{AdmissionClock, Seq, SystemAdmissionClock, WallTime},
    close_adapter_recording_v1, completed_adapter_call_v1,
    crypto::Hash,
    error::CoreError,
    event::{Event, EventDraft, EventOriginV1, Kind},
    geo_admission::{
        GeoLocationAdmissionFingerprintV1, GeoLocationAdmissionIntentV1,
        GeoLocationAdmissionLinkV1, GeoLocationAdmissionOutcome, GeoLocationAdmissionRequestV1,
        GeoLocationAdmissionSnapshotV1, GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1,
        GeoLocationReplayVerifier,
    },
    geo_cell_admission::{
        AdmissionConsentRecordV1, AdmissionEntitlementSnapshotV1, AdmissionSnapshotHash,
        AdmissionSnapshotId, GeoCellAdmissionFenceV1, GeographicAdmissionAdmin,
        GeographicAdmissionConsentResolver, GeographicAdmissionOutcome, GeographicAdmissionStore,
        GeographicReplayEvidenceV1, GeographicReplayVerifier, ValidatedGeographicAdmissionV1,
    },
    hasher::Hasher,
    ids::{EventId, TimelineId},
    inspect_artifact_registration_graph_v1, local_cut_owner_intent_digest_v1,
    owntracks_enrollment::{
        OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStateV1, OwnTracksEnrollmentStatusV1,
        OwnTracksEnrollmentStore,
    },
    owntracks_ingress::{
        OwnTracksIngressInputV1, OwnTracksIngressStore, PreparedOwnTracksIngressV1,
    },
    store::{
        checked_append_identity_expires_at, AppendDedupKey, AppendDedupScope, AppendIdentity,
        AppendIntent, AppendOrDuplicateOutcome, EventReadBounds, EventStore, PurgeOutcome,
        SeqRange,
    },
    timeline::{Timeline, TimelineMeta},
    validate_artifact_registration_catalog_graph_v1, validate_closed_adapter_recording_v1,
    validate_local_cut_owner_result_v1, validate_local_cut_owner_successor_v1,
    validate_manifest_owner_admission_snapshot_v1, AdapterCallReservationOutcomeV1,
    AdapterCallReservationV1, AdapterRecordingSessionV1, AdapterRecordingStoreErrorV1,
    AdapterRecordingStoreV1, AdapterTranscriptCallV1, AdapterTranscriptV1,
    ArtifactRegistrationCatalogRowV1, ArtifactRegistrationCommitOutcomeV1,
    ArtifactRegistrationGraphNodeV1, ArtifactRegistrationPersistenceErrorV1,
    ArtifactRegistrationPersistencePortV1, AuthorityCommitOutcomeV1, AuthorityMutationPermitV1,
    AuthorityPersistenceBindingV1, AuthorityPersistenceErrorV1, AuthorityPersistencePortV1,
    AuthorityPersistenceStateV1, CapabilityGrantV1, CapabilityRevocationV1, ConsentAppendPermit,
    ErasureArtifactClassV1, ErasureCasOutcomeV1, ErasureContainmentGateV1, ErasureErrorV1,
    ErasureForkPersistencePortV1, ErasureForkRecoveryProofV1, ErasureForkRecoveryV1, ErasureGate,
    ErasureIndexInsertV1, ErasureInventoryPersistencePortV1, ErasurePersistedStateV1,
    ErasurePersistenceInventorySnapshotV1, ErasurePersistenceObjectV1, ErasurePersistencePortV1,
    ErasureProtectedOperationV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureStateResolverV1, ErasureTopologyStoreBindingV1, ErasureTopologyTransitionPermitV1,
    ErasureVerifiedInventoryV1, EventOriginRecordV1, ForkAdmissionHostCommandV1,
    ForkAdmissionHostRecordV1, ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1,
    ForkAdmissionOperationKindV1, ForkAdmissionOperationResultV1, ForkAdmissionReceiptV1,
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAdmissionRecoveryProofV1,
    ForkAppendOperationV1, ForkAppendSourceIdentityV1, ForkAttributionOriginV1,
    ForkAuthorityOriginV1, ForkClassifiedEventV1, ForkClassifiedProvenanceV1,
    ForkClassifierRegistrationInputV1, ForkClassifierRegistrationV1, ForkClassifierSourceV1,
    ForkClassifierTableV1, ForkEventClassifierV1, ForkInterventionAdmissionV1,
    ForkPublicationArtifactV1, ForkPublicationBindingV1, ForkPublicationOperationV1,
    ForkPublicationReceiptV1, KeyIdentityV1, KeyRegistryErrorV1,
    KeyRegistryHistoricalDecryptionPortV1, KeyRegistryStateV1, LocalCutOwnerCommitKindV1,
    LocalCutOwnerCommitV1, LocalCutOwnerErrorV1, LocalCutOwnerPersistencePortV1,
    LocalCutOwnerRequestV1, LocalCutOwnerStateV1, ManifestOwnerAdmissionCommitKindV1,
    ManifestOwnerAdmissionCommitV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionOwnerStateV1, ManifestOwnerAdmissionPersistencePortV1,
    ManifestOwnerAdmissionSnapshotV1, OwnerIdV1, PersistedAuthorityV1,
    PreparedArtifactRegistrationBatchV1, PreparedErasureCasV1, PreparedErasureForkBatchV1,
    PreparedErasureRecoveryErrorV1, PreparedLocalCutOwnerCommitV1,
    PreparedManifestOwnerAdmissionV1, PrincipalOwnerBindingInputV1, PrincipalOwnerBindingV1,
    PublicKey, ReproManifestRootV1, Signature, StoredErasureManifestV1,
    ERASURE_MAX_INVENTORY_REQUESTS, ERASURE_MAX_RECOVERY_ERRORS, GEOGRAPHIC_EVENT_TYPE,
};

use crate::fork_admission_authority::{
    admitted_fork_context_containment, admitted_fork_may_have_changed_topology, advance_wall_fence,
    begin_initialize, begin_open, finalize_initialize, finalize_open, fork_commitment,
    principal_owner_commitment, validate_live_session, verify_command, verify_recovery_proof,
    with_unfenced_fork_containment, ForkAdmissionAuthorityBootstrapPortV1,
    ForkAdmissionAuthorityErrorV1, ForkAdmissionAuthorityPortV1, ForkAdmissionAuthoritySessionV1,
    ForkAdmissionAuthorityStateV1, ForkAdmissionOperationRowV1, VerifiedForkAdmissionCommandV1,
};
use crate::fork_delivery_journal::{
    fork_delivery_execution, fork_delivery_may_have_changed_topology,
    ForkAdmissionDeliveryJournalPortV1, ForkDeliveryClaimOutcomeV1, ForkDeliveryClaimV1,
    ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1, ForkDeliveryRowV1,
    ForkDeliveryStartupOutcomeV1, ForkDeliveryStateV1, ForkDeliveryTupleV1,
};
use crate::fork_event_authority::{
    classified_event_matches_operation, fork_append_request, permitted_fork_admission,
    preflight_classifier_sources, recover_classified_operation,
};
use crate::fork_manifest_publication::{
    authorize_publication, publication_parent_head, publication_sources,
    recovered_publication_receipt, require_absent_publication_graph, sign_publication,
    trusted_committed_manifest, validate_publication_request, AbsentPublicationPreflightV1,
    CommittedPublicationRowsV1, CommittedPublicationSourcesV1, PublicationGraphV1,
    PublicationSourceErrorV1, PublicationSourceResultV1, PublicationSourcesV1, PublicationSuffixV1,
};
use crate::{
    ForkAppendSourcePermitV1, ForkClassifiedAppendReceiptV1, ForkClassifierRegistrarPermitV1,
    ForkClassifierRegistrationReceiptV1, ForkEventAuthorityErrorV1,
    ForkEventProvenanceAuthorityPortV1, ForkManifestPublicationErrorV1,
    ForkManifestPublicationPortV1, ForkManifestPublicationRequestV1, HeldRegistryAuthorizationV1,
};

mod fork_attribution_issuer_policy;
mod pipeline_admission;

#[cfg(test)]
thread_local! {
    /// Test-only evidence that bounded reads inspect only selected Event slots.
    static BOUNDED_EVENTS_EXAMINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to prove the elapsed bound covers Event materialization.
    static BOUNDED_CLONE_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the planning elapsed guard.
    static BOUNDED_PLAN_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the fork-chain elapsed guard.
    static BOUNDED_CHAIN_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the per-Event planning elapsed guard.
    static BOUNDED_EVENT_DELAY_MILLIS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the materialization-start elapsed guard.
    static BOUNDED_MATERIALIZE_START_DELAY_MILLIS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    /// Test-only delay used to exercise the final materialization elapsed guard.
    static BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    /// Test-only fault injection for the next unchecked chain-hash lookup.
    static FAIL_NEXT_CHAIN_HASH_AT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only fault injection for the next visible Timeline deletion.
    static FAIL_NEXT_VISIBLE_DELETE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn bounded_clone_delay_for_test() {
    let delay_millis = BOUNDED_CLONE_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_plan_delay_for_test() {
    let delay_millis = BOUNDED_PLAN_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_chain_delay_for_test() {
    let delay_millis = BOUNDED_CHAIN_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_event_delay_for_test() {
    let delay_millis = BOUNDED_EVENT_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_materialize_start_delay_for_test() {
    let delay_millis = BOUNDED_MATERIALIZE_START_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn bounded_materialize_final_delay_for_test() {
    let delay_millis = BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS.with(std::cell::Cell::get);
    if delay_millis != 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay_millis));
    }
}

#[cfg(test)]
fn fail_next_chain_hash_at_for_test() {
    FAIL_NEXT_CHAIN_HASH_AT.with(|fail| fail.set(true));
}

#[cfg(test)]
fn fail_next_visible_delete_for_test() {
    FAIL_NEXT_VISIBLE_DELETE.with(|fail| fail.set(true));
}

/// In-memory event store. Thread-unsafe — intended for single-threaded tests and benchmarks.
pub struct MemoryStore {
    /// Complete state per timeline. Keeping this together makes missing companion state
    /// unrepresentable.
    timelines: HashMap<TimelineId, TimelineState>,
    /// Global `EventId` index for O(1) uniqueness checks.
    event_ids: HashSet<EventId>,
    /// Opaque append identities retained only until their fixed horizon.
    append_identities: HashMap<AppendDedupKey, AppendIdentityRecord>,
    /// Durable-equivalent markers for bounded revocation cleanup continuation.
    pending_append_identity_cleanup: Vec<AppendDedupScope>,
    /// Durable-equivalent marker for Timelines containing protected evidence.
    geographic_timelines: HashSet<TimelineId>,
    /// The sole current authorization state for protected geographic admission.
    owntracks_enrollment: OwnTracksEnrollmentStateV1,
    /// Private keyed deduplication records for protected geographic admission.
    geographic_admission_dedup:
        HashMap<GeoLocationAdmissionFingerprintV1, GeographicAdmissionDedupRecord>,
    /// Immutable admission snapshots, retained for the lifetime of their Event.
    geographic_admission_snapshots: HashMap<EventId, GeoLocationAdmissionSnapshotV1>,
    /// Immutable Event-to-snapshot links, uniquely keyed by `(TimelineId, EventId)`.
    geographic_admission_links: HashMap<(TimelineId, EventId), GeoLocationAdmissionLinkV1>,
    /// Current core-owned binding/consent/entitlement fences for `geo.cell`.
    geographic_cell_fences: HashMap<(TimelineId, pos_core::EntityId), GeoCellAdmissionFenceV1>,
    /// Typed local adapter view of the authoritative immutable consent resolver.
    geographic_cell_consent_records: HashMap<(AdmissionSnapshotId, u64), AdmissionConsentRecordV1>,
    /// Private seven-day exact-intent deduplication for `geo.cell`.
    geographic_cell_dedup:
        HashMap<pos_core::GeographicAdmissionFingerprintV1, GeographicCellDedupRecord>,
    /// Immutable `geo.cell` admission snapshots keyed by their canonical ID.
    geographic_cell_snapshots: HashMap<AdmissionSnapshotId, AdmissionEntitlementSnapshotV1>,
    /// Immutable `geo.cell` Event-to-snapshot links.
    geographic_cell_links: HashMap<(TimelineId, EventId), GeographicCellLink>,
    /// Trusted Gateway authority bound to this adapter's protected append port.
    consent_authority_permit: Option<ConsentAppendPermit>,
    /// Host-owned erasure containment gate for protected Timeline operations.
    erasure_gate: Option<Arc<ErasureContainmentGateV1>>,
    /// Whether the current gate was supplied by the host. The constructor's
    /// local gate is replaceable exactly once by the composition root.
    erasure_gate_bound: bool,
    /// Inventory generation captured by the last complete host snapshot.
    erasure_inventory_generation: Option<ErasureReferenceV1>,
    /// Host-managed topology may only change through verified transitions.
    erasure_topology_requires_permit: bool,
    /// Opaque host-issued identity for this adapter's topology transitions.
    erasure_topology_store_binding: Option<ErasureTopologyStoreBindingV1>,
    /// Durable-equivalent owner-scoped key registry for adapter tests.
    key_registry: Option<KeyRegistryStateV1>,
    /// Canonical authority records shared with the durable adapter contract.
    authority_state: AuthorityPersistenceStateV1,
    /// Host-published ADR-021 admission fences keyed by Timeline.
    pipeline_admission_fences: HashMap<TimelineId, pos_core::PipelineAdmissionFenceV1>,
    /// Retained ADR-021 admitted-batch receipts keyed by opaque idempotency key.
    pipeline_admission_receipts:
        HashMap<AppendDedupKey, pipeline_admission::PipelineReceiptRecordV1>,
    /// Opaque trusted-host capability bound to authority mutations.
    authority_persistence_binding: Option<AuthorityPersistenceBindingV1>,
    /// ADR-106 bootstrap root, one-use challenges, session, and rollback fence.
    fork_admission_authority: ForkAdmissionAuthorityStateV1,
    /// Public custom admission clocks are never Fork-authority clocks.
    fork_admission_authority_enabled: bool,
    /// Private POB1 rows indexed by authenticated Principal digest.
    fork_principal_owner_bindings: HashMap<Hash, PrincipalOwnerBindingV1>,
    /// Keyed POB1 lookup: POB1 digest to its authenticated Principal digest.
    fork_principal_owner_binding_digests: HashMap<Hash, Hash>,
    /// Private FAR1 rows indexed by allocated child Timeline.
    fork_admissions: HashMap<TimelineId, ForkAdmissionRecordV1>,
    /// Durable-equivalent operation roots keyed by `(kind, operation ID)`.
    fork_admission_operations:
        HashMap<(ForkAdmissionOperationKindV1, Hash), ForkAdmissionOperationRowV1>,
    /// Private tuple-only local listener delivery journal.
    fork_delivery_journal: HashMap<Hash, ForkDeliveryRowV1>,
    /// Never-reused local listener ownership fence, including purged rows.
    fork_delivery_last_fence: u64,
    fork_classifier_sources: HashMap<(Hash, String), ForkClassifierSourceV1>,
    fork_classifier_tables: HashMap<TimelineId, ForkClassifierTableV1>,
    fork_classifier_registrations: HashMap<Hash, ForkClassifierRegistrationV1>,
    fork_append_operations: HashMap<Hash, ForkAppendOperationV1>,
    fork_event_origins: HashMap<EventId, EventOriginRecordV1>,
    fork_intervention_admissions: HashMap<EventId, ForkInterventionAdmissionV1>,
    fork_publication_operations: HashMap<Hash, ForkPublicationOperationV1>,
    fork_publication_bindings: HashMap<(TimelineId, u64), ForkPublicationBindingV1>,
    fork_publication_artifacts: HashMap<Hash, ForkPublicationArtifactV1>,
    /// Accepted ADR-105 `FIP1` history; index `g - 1` holds generation `g`,
    /// and the last entry is the durable floor.
    fork_attribution_issuer_policies: Vec<pos_core::ForkAttributionIssuerPolicyV1>,
    /// Current raw ERCRP1 envelope per request.
    erasure_records: BTreeMap<ErasureReferenceV1, (ErasureReferenceV1, Vec<u8>)>,
    /// Independently bounded content-addressed erasure supporting evidence.
    erasure_evidence: BTreeMap<ErasureReferenceV1, Vec<u8>>,
    /// Exact immutable artifact bytes and ARD1 rows visible in each local owner catalog.
    artifact_registrations: BTreeMap<Hash, ArtifactRegistrationCatalogRowV1>,
    /// Unique immutable identity index for `(owner, class, artifact digest)`.
    artifact_registration_identities: BTreeMap<(OwnerIdV1, ErasureArtifactClassV1, Hash), Hash>,
    /// Immutable `(owner, MRM1 operation ID) -> root registration` index.
    artifact_registration_operations: BTreeMap<(OwnerIdV1, Hash), Hash>,
    /// Current local manifest-owner generation and complete owned Timeline set.
    manifest_owner_admission_states: BTreeMap<[u8; 32], MemoryManifestOwnerAdmissionStateV1>,
    /// Immutable historical MCA1/MSB1/MSR1 rows and exact scoped native copies.
    manifest_owner_admission_snapshots:
        BTreeMap<([u8; 32], u64, TimelineId), ManifestOwnerAdmissionSnapshotV1>,
    /// Idempotent operation outcomes, including the original receipt digests.
    manifest_owner_admission_operations:
        BTreeMap<([u8; 32], Hash), MemoryManifestOwnerAdmissionOperationV1>,
    /// Current local-cut owner state, synchronized with the current admission state.
    local_cut_owner_states: BTreeMap<[u8; 32], LocalCutOwnerStateV1>,
    /// Immutable local-cut batches keyed by owner operation identity.
    local_cut_owner_operations: BTreeMap<([u8; 32], Hash), MemoryLocalCutOwnerOperationV1>,
    /// Immutable visible local-cut results keyed by their owner and cut identity.
    local_cut_owner_commits: BTreeMap<([u8; 32], u64), LocalCutOwnerCommitV1>,
    /// Crash-recoverable local adapter recorder sessions by owner/run ID.
    adapter_recording_sessions: BTreeMap<(Hash, Hash), MemoryAdapterRecordingSessionV1>,
    /// Canonical ERS1 history needed to validate predecessor links after restart.
    erasure_states: BTreeMap<ErasureReferenceV1, Vec<u8>>,
    erasure_attempt_pages: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    erasure_scope_nodes: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    erasure_administrative_resolutions: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    erasure_effects: BTreeMap<ErasureReferenceV1, (ErasureReferenceV1, Vec<u8>)>,
    erasure_effect_subjects: BTreeMap<ErasureReferenceV1, ErasureReferenceV1>,
    erasure_recovery_errors: BTreeMap<ErasureReferenceV1, BTreeSet<ErasureReferenceV1>>,
    /// Stable Fork operation identity to complete prepared-admission binding.
    erasure_fork_admissions: BTreeMap<ErasureReferenceV1, ErasureForkRecoveryV1>,
    /// Complete prepared Fork proof retained for exact post-commit recovery.
    erasure_fork_recovery_proofs: BTreeMap<ErasureReferenceV1, ErasureForkRecoveryProofV1>,
    hasher: Box<dyn Hasher>,
    clock: Box<dyn AdmissionClock>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryAdapterRecordingStatusV1 {
    Open,
    Closed,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoryAdapterRecordingCallV1 {
    reservation: AdapterCallReservationV1,
    output_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoryAdapterRecordingSessionV1 {
    session: AdapterRecordingSessionV1,
    status: MemoryAdapterRecordingStatusV1,
    calls: BTreeMap<u64, MemoryAdapterRecordingCallV1>,
    transcript_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoryManifestOwnerAdmissionStateV1 {
    configuration_generation: u64,
    previous_visible_lcq1_hash: Option<Hash>,
    inventory_generation: Hash,
    timelines: BTreeSet<TimelineId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoryManifestOwnerAdmissionOperationV1 {
    intent_digest: Hash,
    result: ManifestOwnerAdmissionCommitV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MemoryLocalCutOwnerOperationV1 {
    intent_digest: Hash,
    request: LocalCutOwnerRequestV1,
    result: LocalCutOwnerCommitV1,
}

#[derive(Clone, Copy)]
struct BoundedSegmentPage {
    timeline: TimelineId,
    raw_start: u64,
    take: usize,
    logical_offset: u64,
}

struct BoundedSegmentRequest<'a> {
    chain: &'a [TimelineId],
    index: usize,
    timeline: TimelineId,
    logical_offset: u64,
    from: u64,
    to: u64,
    remaining: usize,
    bounds: EventReadBounds,
    started: Instant,
    total_bytes: &'a mut usize,
}

fn bounded_elapsed_error(started: Instant, maximum_micros: u64) -> Option<CoreError> {
    let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    (elapsed_micros > maximum_micros).then_some(CoreError::ReadTimeTooLarge { elapsed_micros })
}

#[inline(never)]
fn read_event_by_id(
    store: &MemoryStore,
    timeline: TimelineId,
    event_id: EventId,
) -> Result<Option<Event>, CoreError> {
    store
        .ensure_generic_timeline_visibility(timeline)
        .and_then(|()| store.fork_chain(timeline))
        .and_then(|chain| {
            for (index, timeline_id) in chain.timelines.iter().enumerate() {
                let prefix = chain.segment_prefix(index)?;
                let limit = chain.segment_length(store, index, *timeline_id)?;
                if let Some(event) = store
                    .state(*timeline_id)
                    .events
                    .iter()
                    .find(|event| event.seq.as_u64() <= limit && event.id == event_id)
                    .cloned()
                {
                    return MemoryStore::logical_event(prefix, event).map(Some);
                }
            }
            Ok(None)
        })
}

#[inline(never)]
fn read_own(
    store: &MemoryStore,
    timeline: TimelineId,
    range: SeqRange,
) -> Result<Vec<Event>, CoreError> {
    store
        .ensure_generic_timeline_visibility(timeline)
        .map(|()| {
            store
                .state(timeline)
                .events
                .iter()
                .filter(|event| {
                    event.seq >= range.from && (range.to.is_none() || range.to >= Some(event.seq))
                })
                .cloned()
                .collect()
        })
}

fn has_child_timeline(timelines: &HashMap<TimelineId, TimelineState>, parent: TimelineId) -> bool {
    for state in timelines.values() {
        let Some((child_parent, _)) = state.timeline.meta.fork_point else {
            continue;
        };
        if child_parent == parent {
            return true;
        }
    }
    false
}

fn mutable_state(
    timelines: &mut HashMap<TimelineId, TimelineState>,
    id: TimelineId,
) -> Result<&mut TimelineState, CoreError> {
    timelines
        .get_mut(&id)
        .ok_or(CoreError::TimelineNotFound(id))
}

#[inline(never)]
fn delete_timeline(store: &mut MemoryStore, id: TimelineId) -> Result<(), CoreError> {
    store
        .ensure_admin_visibility(id)
        .and_then(|()| delete_visible_timeline(store, id))
}

fn delete_visible_timeline(store: &mut MemoryStore, id: TimelineId) -> Result<(), CoreError> {
    delete_visible_timeline_impl(store, id)
}

fn delete_visible_timeline_impl(store: &mut MemoryStore, id: TimelineId) -> Result<(), CoreError> {
    #[cfg(test)]
    if FAIL_NEXT_VISIBLE_DELETE.with(|fail| fail.replace(false)) {
        return Err(CoreError::Storage(
            "injected visible Timeline deletion failure".to_owned(),
        ));
    }
    if has_child_timeline(&store.timelines, id) {
        return Err(CoreError::Storage(
            "cannot delete timeline that still has forks".to_owned(),
        ));
    }
    store
        .timelines
        .remove(&id)
        .ok_or(CoreError::TimelineNotFound(id))
        .map(|state| {
            let event_ids: HashSet<_> = state.events.iter().map(|event| event.id).collect();
            store
                .event_ids
                .retain(|event_id| !event_ids.contains(event_id));
            let existing_identities = std::mem::take(&mut store.append_identities);
            let mut retained_identities = HashMap::with_capacity(existing_identities.len());
            for (key, record) in existing_identities {
                if !event_ids.contains(&record.event_id) {
                    retained_identities.insert(key, record);
                }
            }
            store.append_identities = retained_identities;
            store.forget_pipeline_admission_timeline(id);
            store.geographic_timelines.remove(&id);
            if store
                .owntracks_enrollment
                .permits_geographic_admission_target(id)
            {
                store.owntracks_enrollment = store
                    .owntracks_enrollment
                    .clone()
                    .revoke()
                    .unwrap_or_else(|_| OwnTracksEnrollmentStateV1::absent());
            }
            store
                .geographic_admission_dedup
                .retain(|_, record| record.timeline != id);
            store
                .geographic_admission_snapshots
                .retain(|event_id, _| !event_ids.contains(event_id));
            store
                .geographic_admission_links
                .retain(|(timeline, event_id), _| *timeline != id && !event_ids.contains(event_id));
            store
                .geographic_cell_fences
                .retain(|(timeline, _), _| *timeline != id);
            store
                .geographic_cell_dedup
                .retain(|_, record| record.timeline != id);
            store
                .geographic_cell_snapshots
                .retain(|_, snapshot| snapshot.timeline() != id);
            // Consent records are authoritative resolver state. Their lifecycle
            // is owned by the ADR-034 resolver, not by Timeline sidecar cleanup.
            store
                .geographic_cell_links
                .retain(|(timeline, event_id), _| *timeline != id && !event_ids.contains(event_id));
        })
}

#[derive(Clone)]
struct AppendIdentityRecord {
    timeline: TimelineId,
    scope: AppendDedupScope,
    event_id: EventId,
    expires_at: WallTime,
    retained_content: RetainedAppendContent,
}

#[derive(Clone)]
struct GeographicCellDedupRecord {
    timeline: TimelineId,
    entity: pos_core::EntityId,
    intent: pos_core::GeographicAdmissionIntentV1,
    event_id: EventId,
    event_seq: Seq,
    snapshot_id: AdmissionSnapshotId,
    snapshot_hash: AdmissionSnapshotHash,
    expires_at: WallTime,
}

#[derive(Clone)]
#[allow(clippy::struct_field_names)]
struct GeographicCellLink {
    snapshot_id: AdmissionSnapshotId,
    snapshot_hash: AdmissionSnapshotHash,
    snapshot_cbor: pos_core::CanonicalBytes,
}

/// Comparison material retained only with an opaque append identity.
#[derive(Clone)]
struct RetainedAppendContent {
    entity: pos_core::EntityId,
    event_type: pos_core::Kind,
    payload: pos_core::CanonicalBytes,
    causation_id: Option<EventId>,
    correlation_id: Option<pos_core::CorrelationId>,
    schema_version: pos_core::SchemaVersion,
}

struct ForkChain {
    timelines: Vec<TimelineId>,
    fork_seqs: Vec<Seq>,
}

impl ForkChain {
    fn segment_prefix(&self, index: usize) -> Result<u64, CoreError> {
        if index == 0 {
            Ok(0)
        } else {
            self.fork_seqs
                .get(index - 1)
                .copied()
                .map(Seq::as_u64)
                .ok_or_else(|| {
                    CoreError::Storage("Fork chain is missing a logical prefix".to_owned())
                })
        }
    }

    fn segment_length(
        &self,
        store: &MemoryStore,
        index: usize,
        timeline: TimelineId,
    ) -> Result<u64, CoreError> {
        let prefix = self.segment_prefix(index)?;
        let local_head = store.state(timeline).timeline.head.as_u64();
        let length = match self.fork_seqs.get(index).copied() {
            Some(fork) => fork.as_u64().checked_sub(prefix).ok_or_else(|| {
                CoreError::Storage(format!(
                    "Fork point precedes inherited history for timeline {timeline}"
                ))
            })?,
            None => local_head,
        };
        if length > local_head {
            return Err(CoreError::Storage(format!(
                "Fork point exceeds parent logical Event head for timeline {timeline}"
            )));
        }
        Ok(length)
    }
}

#[derive(Clone)]
struct TimelineState {
    timeline: Timeline,
    events: Vec<Event>,
    chain_head: Hash,
}

impl TimelineState {
    const fn new(timeline: Timeline, chain_head: Hash) -> Self {
        Self {
            timeline,
            events: Vec::new(),
            chain_head,
        }
    }
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove the containment gate. Protected operations then fail closed until
    /// a host binds its authoritative gate.
    #[must_use]
    pub fn without_erasure_gate(mut self) -> Self {
        self.erasure_gate = None;
        self.erasure_topology_store_binding = None;
        self
    }

    #[must_use]
    fn with_default_components(hasher: Box<dyn Hasher>) -> Self {
        let erasure_gate = Some(Arc::new(ErasureContainmentGateV1::new_fail_closed()));
        let erasure_gate_bound = false;

        Self {
            timelines: HashMap::new(),
            event_ids: HashSet::new(),
            append_identities: HashMap::new(),
            pending_append_identity_cleanup: Vec::new(),
            geographic_timelines: HashSet::new(),
            owntracks_enrollment: OwnTracksEnrollmentStateV1::absent(),
            geographic_admission_dedup: HashMap::new(),
            geographic_admission_snapshots: HashMap::new(),
            geographic_admission_links: HashMap::new(),
            geographic_cell_fences: HashMap::new(),
            geographic_cell_consent_records: HashMap::new(),
            geographic_cell_dedup: HashMap::new(),
            geographic_cell_snapshots: HashMap::new(),
            geographic_cell_links: HashMap::new(),
            consent_authority_permit: None,
            // A store is not allowed to make protected operations available
            // before the composition root supplies the host-owned gate.
            erasure_gate,
            erasure_gate_bound,
            erasure_inventory_generation: None,
            erasure_topology_requires_permit: false,
            erasure_topology_store_binding: None,
            key_registry: None,
            authority_state: AuthorityPersistenceStateV1::new(),
            pipeline_admission_fences: HashMap::new(),
            pipeline_admission_receipts: HashMap::new(),
            authority_persistence_binding: None,
            fork_admission_authority: ForkAdmissionAuthorityStateV1::default(),
            fork_admission_authority_enabled: true,
            fork_principal_owner_bindings: HashMap::new(),
            fork_principal_owner_binding_digests: HashMap::new(),
            fork_admissions: HashMap::new(),
            fork_admission_operations: HashMap::new(),
            fork_delivery_journal: HashMap::new(),
            fork_delivery_last_fence: 0,
            fork_classifier_sources: HashMap::new(),
            fork_classifier_tables: HashMap::new(),
            fork_classifier_registrations: HashMap::new(),
            fork_append_operations: HashMap::new(),
            fork_event_origins: HashMap::new(),
            fork_intervention_admissions: HashMap::new(),
            fork_publication_operations: HashMap::new(),
            fork_publication_bindings: HashMap::new(),
            fork_publication_artifacts: HashMap::new(),
            fork_attribution_issuer_policies: Vec::new(),
            erasure_records: BTreeMap::new(),
            erasure_evidence: BTreeMap::new(),
            artifact_registrations: BTreeMap::new(),
            artifact_registration_identities: BTreeMap::new(),
            artifact_registration_operations: BTreeMap::new(),
            manifest_owner_admission_states: BTreeMap::new(),
            manifest_owner_admission_snapshots: BTreeMap::new(),
            manifest_owner_admission_operations: BTreeMap::new(),
            local_cut_owner_states: BTreeMap::new(),
            local_cut_owner_operations: BTreeMap::new(),
            local_cut_owner_commits: BTreeMap::new(),
            adapter_recording_sessions: BTreeMap::new(),
            erasure_states: BTreeMap::new(),
            erasure_attempt_pages: BTreeMap::new(),
            erasure_scope_nodes: BTreeMap::new(),
            erasure_administrative_resolutions: BTreeMap::new(),
            erasure_effects: BTreeMap::new(),
            erasure_effect_subjects: BTreeMap::new(),
            erasure_recovery_errors: BTreeMap::new(),
            erasure_fork_admissions: BTreeMap::new(),
            erasure_fork_recovery_proofs: BTreeMap::new(),
            hasher,
            clock: Box::new(SystemAdmissionClock),
        }
    }

    #[must_use]
    pub fn with_hasher(hasher: Box<dyn Hasher>) -> Self {
        Self::with_default_components(hasher)
    }

    /// Construct a store with a deterministic or host-provided admission clock.
    #[must_use]
    pub fn with_clock(clock: Box<dyn AdmissionClock>) -> Self {
        let mut store = Self::new();
        store.clock = clock;
        store.fork_admission_authority_enabled = false;
        store
    }

    fn append_or_duplicate_with_limit(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: &EventDraft,
        max_owned_events: Option<u64>,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        crate::ensure_non_geographic_draft(draft, timeline)
            .and_then(|()| self.ensure_generic_fork_append_is_rejected(timeline))
            .and_then(|()| self.ensure_generic_timeline_visibility(timeline))
            .and_then(|()| {
                self.append_or_duplicate_with_limit_visible(
                    timeline,
                    identity,
                    admitted_at,
                    draft,
                    max_owned_events,
                )
            })
    }

    fn append_or_duplicate_with_limit_visible(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: &EventDraft,
        max_owned_events: Option<u64>,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        let logical_prefix = self.logical_prefix(timeline)?;
        if let Some(record) = self.append_identities.get(&identity.dedup_key) {
            if record.expires_at > admitted_at {
                if record.timeline != timeline {
                    return Ok(Some(AppendOrDuplicateOutcome::Conflict));
                }
                return Ok(Some(
                    if Self::retained_content_matches(&record.retained_content, draft) {
                        AppendOrDuplicateOutcome::Duplicate {
                            event_id: record.event_id,
                        }
                    } else {
                        AppendOrDuplicateOutcome::Conflict
                    },
                ));
            }
        }
        if max_owned_events.is_some_and(|maximum| {
            self.timelines
                .get(&timeline)
                .is_some_and(|state| state.timeline.head.as_u64() >= maximum)
        }) {
            return Ok(None);
        }
        let expires_at = checked_append_identity_expires_at(admitted_at)?;
        let event = {
            let (timelines, event_ids, hasher) =
                (&mut self.timelines, &mut self.event_ids, &self.hasher);
            mutable_state(timelines, timeline).and_then(|state| {
                let event = Self::append_one_to_state(state, draft, hasher.as_ref())?;
                event_ids.insert(event.id);
                Ok(event)
            })
        };
        event.and_then(|event| {
            self.append_identities.insert(
                identity.dedup_key,
                AppendIdentityRecord {
                    timeline,
                    scope: identity.scope,
                    event_id: event.id,
                    expires_at,
                    retained_content: Self::retained_content(&event),
                },
            );
            Self::logical_event(logical_prefix, event)
                .map(|event| Some(AppendOrDuplicateOutcome::Appended(Box::new(event))))
        })
    }

    fn timeline(&self, id: TimelineId) -> Result<&Timeline, CoreError> {
        self.timelines
            .get(&id)
            .map_or(Err(CoreError::TimelineNotFound(id)), |state| {
                Ok(&state.timeline)
            })
    }

    fn logical_prefix(&self, timeline: TimelineId) -> Result<u64, CoreError> {
        self.timeline(timeline).map(|timeline| {
            timeline
                .meta
                .fork_point
                .map_or(0, |(_, fork)| fork.as_u64())
        })
    }

    fn logical_event(prefix: u64, mut event: Event) -> Result<Event, CoreError> {
        event.seq =
            Seq::from_u64(prefix.checked_add(event.seq.as_u64()).ok_or_else(|| {
                CoreError::Storage("logical Timeline sequence overflow".to_owned())
            })?);
        Ok(event)
    }

    /// Borrow complete state after the caller has validated the Timeline id.
    fn state(&self, id: TimelineId) -> &TimelineState {
        &self.timelines[&id]
    }

    /// Mutably borrow complete state after the caller has validated the Timeline id.
    fn state_mut(&mut self, id: TimelineId) -> Result<&mut TimelineState, CoreError> {
        mutable_state(&mut self.timelines, id)
    }

    fn checked_signing_registry(
        &self,
        expected: &KeyRegistryStateV1,
    ) -> Result<KeyRegistryStateV1, CoreError> {
        self.load_key_registry()
            .and_then(|registry| {
                registry.ok_or_else(|| CoreError::Storage("key registry is unavailable".to_owned()))
            })
            .and_then(|persisted| {
                if persisted == *expected {
                    Ok(persisted)
                } else {
                    Err(CoreError::Storage(
                        "key registry changed during signing".to_owned(),
                    ))
                }
            })
    }

    fn append_one_to_state(
        state: &mut TimelineState,
        draft: &EventDraft,
        hasher: &dyn Hasher,
    ) -> Result<Event, CoreError> {
        Self::prepare_one_for_state(state, draft, hasher).map(|(event, chain_head)| {
            Self::commit_prepared_to_state(state, event.clone(), chain_head);
            event
        })
    }

    /// Commit an Event previously prepared against this exact Timeline head.
    fn commit_prepared_to_state(state: &mut TimelineState, event: Event, chain_head: Hash) {
        state.chain_head = chain_head;
        state.timeline.head = event.seq;
        state.events.push(event);
    }

    /// Build the next Event and chain head without mutating Timeline state.
    fn prepare_one_for_state(
        state: &TimelineState,
        draft: &EventDraft,
        hasher: &dyn Hasher,
    ) -> Result<(Event, Hash), CoreError> {
        let seq = state.timeline.head.next();
        crate::checked_logical_head(
            state
                .timeline
                .meta
                .fork_point
                .map_or(0, |(_, fork)| fork.as_u64()),
            seq.as_u64(),
        )
        .map(|origin_logical_seq| {
            let event_id = EventId::new();
            let id_bytes = event_id.to_string();
            let payload_hash = hasher.hash_payload(&draft.payload);
            let chain_head =
                hasher.hash_event(&state.chain_head, id_bytes.as_bytes(), &draft.payload);
            let event = Event {
                id: event_id,
                entity: draft.entity,
                event_type: draft.event_type.clone(),
                payload: draft.payload.clone(),
                wall_time: draft.wall_time.unwrap_or_else(WallTime::now),
                seq,
                causation_id: draft.causation_id,
                correlation_id: draft.correlation_id,
                schema_version: draft.schema_version,
                signature: None,
                signature_identity: None,
                origin: Some(EventOriginV1 {
                    origin_timeline_id: state.timeline.id(),
                    origin_logical_seq: Seq::from_u64(origin_logical_seq),
                }),
                payload_hash,
            };
            (event, chain_head)
        })
    }

    fn chain_head(&self, id: TimelineId) -> Hash {
        self.state(id).chain_head
    }

    fn retained_content_matches(content: &RetainedAppendContent, draft: &EventDraft) -> bool {
        content.entity == draft.entity
            && content.event_type == draft.event_type
            && content.payload == draft.payload
            && content.causation_id == draft.causation_id
            && content.correlation_id == draft.correlation_id
            && content.schema_version == draft.schema_version
    }

    fn retained_content(event: &Event) -> RetainedAppendContent {
        RetainedAppendContent {
            entity: event.entity,
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
            causation_id: event.causation_id,
            correlation_id: event.correlation_id,
            schema_version: event.schema_version,
        }
    }

    /// Collect all events for a timeline, walking the fork chain.
    /// Returns events sorted by seq, stitching parent `0..fork_seq` + child events.
    fn collect_events_in_range(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
    ) -> Result<Vec<Event>, CoreError> {
        // Collect the chain of timelines from root to this one
        let chain = self.fork_chain(timeline_id)?;

        // Build the full logical event sequence
        chain
            .timelines
            .iter()
            .enumerate()
            .try_fold(Vec::new(), |mut all, (i, tid)| {
                self.timeline(*tid).and_then(|_| {
                    let state = self.state(*tid);
                    let events = &state.events;
                    let length = chain.segment_length(self, i, *tid)?;
                    all.extend(
                        events
                            .iter()
                            .filter(|event| event.seq.as_u64() <= length)
                            .cloned(),
                    );
                    Ok(all)
                })
            })
            .map(|all| crate::stitch::renumber_and_filter(all, range))
    }

    /// Select a logical page without cloning Events outside the requested range.
    fn collect_events_in_range_bounded(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        let started = Instant::now();
        if bounds.max_elapsed_micros() == 0 {
            return Err(CoreError::ReadTimeTooLarge { elapsed_micros: 0 });
        }
        let chain = self.fork_chain_bounded(
            timeline_id,
            bounds.max_fork_depth(),
            started,
            bounds.max_elapsed_micros(),
        )?;
        self.plan_bounded_events(&chain, range, bounds, started)
            .and_then(|plans| self.materialize_bounded_events(&plans, bounds, started))
    }

    fn plan_bounded_events(
        &self,
        chain: &[TimelineId],
        range: SeqRange,
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<Vec<BoundedSegmentPage>, CoreError> {
        let from = range.from.as_u64().max(1);
        let to = range.to.map_or(u64::MAX, Seq::as_u64);
        let mut logical_offset = 0_u64;
        let mut remaining = bounds.max_events();
        let mut total_bytes = 0_usize;
        let mut plans = Vec::new();

        for (index, timeline) in chain.iter().enumerate() {
            let planned = self.plan_bounded_segment(BoundedSegmentRequest {
                chain,
                index,
                timeline: *timeline,
                logical_offset,
                from,
                to,
                remaining,
                bounds,
                started,
                total_bytes: &mut total_bytes,
            })?;
            if let Some(plan) = planned {
                remaining -= plan.take;
                plans.push(plan);
            }
            let segment_len =
                self.bounded_segment_length(chain, index, *timeline, logical_offset)?;
            logical_offset = logical_offset.saturating_add(segment_len);
            if remaining == 0 || logical_offset >= to {
                break;
            }
        }
        Ok(plans)
    }

    fn plan_bounded_segment(
        &self,
        request: BoundedSegmentRequest<'_>,
    ) -> Result<Option<BoundedSegmentPage>, CoreError> {
        let BoundedSegmentRequest {
            chain,
            index,
            timeline,
            logical_offset,
            from,
            to,
            remaining,
            bounds,
            started,
            total_bytes,
        } = request;
        #[cfg(test)]
        bounded_plan_delay_for_test();
        if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
            return Err(error);
        }
        let state = self.state(timeline);
        let events = &state.events;
        let event_count = u64::try_from(events.len()).unwrap_or(u64::MAX);
        let boundary_is_valid = if events.is_empty() {
            state.timeline.head == Seq::ZERO
        } else {
            state.timeline.head.as_u64() == event_count
                && events[0].seq == Seq::from_u64(1)
                && events[events.len() - 1].seq == Seq::from_u64(event_count)
        };
        if !boundary_is_valid {
            return Err(CoreError::Storage(format!(
                "timeline {timeline} violates the contiguous Event sequence invariant"
            )));
        }
        let segment_len = self.bounded_segment_length(chain, index, timeline, logical_offset)?;
        let Some(page) = crate::stitch::plan_page(logical_offset, segment_len, from, to, remaining)
        else {
            return Ok(None);
        };
        let start_index = usize::try_from(page.raw_start - 1).unwrap_or(usize::MAX);
        let end_index = start_index.saturating_add(page.take);
        let slice = &events[start_index..end_index];
        for (offset, event) in slice.iter().enumerate() {
            #[cfg(test)]
            bounded_event_delay_for_test();
            if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
                return Err(error);
            }
            #[cfg(test)]
            BOUNDED_EVENTS_EXAMINED.with(|count| count.set(count.get().saturating_add(1)));
            let raw_seq = page
                .raw_start
                .saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
            if event.seq != Seq::from_u64(raw_seq) {
                return Err(CoreError::Storage(format!(
                    "timeline {timeline} violates the contiguous Event sequence invariant"
                )));
            }
            let payload_size = event.payload.as_slice().len();
            if payload_size > bounds.max_payload_bytes() {
                return Err(CoreError::PayloadTooLarge { size: payload_size });
            }
            let event_type_size = event.event_type.as_str().len();
            if event_type_size > bounds.max_event_type_bytes() {
                return Err(CoreError::EventMetadataTooLarge {
                    field: "event_type",
                    size: event_type_size,
                });
            }
            *total_bytes =
                (*total_bytes).saturating_add(payload_size.saturating_add(event_type_size));
            if *total_bytes > bounds.max_total_bytes() {
                return Err(CoreError::ReadBytesTooLarge { size: *total_bytes });
            }
        }
        Ok(Some(BoundedSegmentPage {
            timeline,
            raw_start: page.raw_start,
            take: page.take,
            logical_offset,
        }))
    }

    fn bounded_segment_length(
        &self,
        chain: &[TimelineId],
        index: usize,
        timeline: TimelineId,
        logical_offset: u64,
    ) -> Result<u64, CoreError> {
        let event_count = u64::try_from(self.state(timeline).events.len()).unwrap_or(u64::MAX);
        let fork_cap = chain.get(index + 1).and_then(|child| {
            self.timelines[child]
                .timeline
                .meta
                .fork_point
                .map(|(_, seq)| seq)
        });
        let segment_len = fork_cap.map_or(Ok(event_count), |cap| {
            cap.as_u64().checked_sub(logical_offset).ok_or_else(|| {
                CoreError::Storage(format!(
                    "Fork point precedes inherited history for timeline {timeline}"
                ))
            })
        })?;
        if segment_len > event_count {
            return Err(CoreError::Storage(format!(
                "Fork point exceeds parent logical Event head for timeline {timeline}"
            )));
        }
        Ok(segment_len)
    }

    fn materialize_bounded_events(
        &self,
        plans: &[BoundedSegmentPage],
        bounds: EventReadBounds,
        started: Instant,
    ) -> Result<Vec<Event>, CoreError> {
        let mut selected = Vec::new();
        for plan in plans {
            #[cfg(test)]
            bounded_materialize_start_delay_for_test();
            if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
                return Err(error);
            }
            let events = &self.state(plan.timeline).events;
            let start_index = usize::try_from(plan.raw_start - 1).unwrap_or(usize::MAX);
            let end_index = start_index.saturating_add(plan.take);
            for event in &events[start_index..end_index] {
                let mut event = event.clone();
                #[cfg(test)]
                bounded_clone_delay_for_test();
                event.seq = Seq::from_u64(plan.logical_offset.saturating_add(event.seq.as_u64()));
                selected.push(event);
                if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
                    return Err(error);
                }
            }
        }
        #[cfg(test)]
        bounded_materialize_final_delay_for_test();
        if let Some(error) = bounded_elapsed_error(started, bounds.max_elapsed_micros()) {
            return Err(error);
        }
        Ok(selected)
    }

    fn append_bounded_with_boundary(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        max_owned_events: u64,
        gateway_consent: bool,
        permit: Option<ConsentAppendPermit>,
        cleanup_scope: Option<AppendDedupScope>,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        if gateway_consent {
            let bound_permit = self.consent_authority_permit.ok_or_else(|| {
                CoreError::Storage("Gateway consent authority is not bound".to_owned())
            })?;
            let permit = permit.ok_or_else(|| {
                CoreError::Storage("Gateway consent append permit is missing".to_owned())
            })?;
            if permit != bound_permit {
                return Err(CoreError::Storage(
                    "Gateway consent append permit does not match the bound authority".to_owned(),
                ));
            }
        }
        let validate = if gateway_consent {
            crate::ensure_gateway_consent_types
        } else {
            crate::ensure_non_geographic_drafts
        };
        validate(drafts, timeline)
            .and_then(|()| self.ensure_generic_fork_append_is_rejected(timeline))
            .and_then(|()| {
                if gateway_consent {
                    self.timeline(timeline).map(|_| ())
                } else {
                    self.ensure_generic_timeline_visibility(timeline)
                }
            })
            .and_then(|()| {
                // Visibility checked this key immediately above and no mutation
                // occurs between the check and this read.
                let timeline_state = &self.timelines[&timeline].timeline;
                let owned_head = timeline_state.head.as_u64();
                let logical_prefix = timeline_state
                    .meta
                    .fork_point
                    .map_or(0, |(_, fork)| fork.as_u64());
                let batch_len = u64::try_from(drafts.len()).unwrap_or(u64::MAX);
                let owner = if gateway_consent {
                    Some(crate::ensure_gateway_consent_drafts(
                        drafts,
                        timeline,
                        timeline_state.meta.owner,
                        logical_prefix.saturating_add(owned_head).saturating_add(1),
                    )?)
                } else {
                    None
                };
                if let Some(next_head) =
                    crate::bounded_owned_head(owned_head, batch_len, max_owned_events)?
                {
                    crate::checked_logical_head(logical_prefix, next_head)?;
                    let events =
                        self.append_visible_with_prefix(timeline, drafts, logical_prefix)?;
                    if let Some(scope) = cleanup_scope {
                        if !self.pending_append_identity_cleanup.contains(&scope) {
                            self.pending_append_identity_cleanup.push(scope);
                        }
                    }
                    if let Some(owner) = owner {
                        if let Some(state) = self.timelines.get_mut(&timeline) {
                            state.timeline.meta.owner = Some(owner);
                        }
                    }
                    Ok(Some(events))
                } else {
                    Ok(None)
                }
            })
    }

    /// Walk the fork chain from `timeline_id` back to the root, returning [root, ..., `timeline_id`].
    fn fork_chain(&self, timeline_id: TimelineId) -> Result<ForkChain, CoreError> {
        let mut chain = Vec::new();
        let mut fork_seqs = Vec::new();
        let mut visited = HashSet::new();
        let mut current = timeline_id;
        loop {
            if !visited.insert(current) {
                return Err(CoreError::Storage(format!(
                    "fork ancestry contains a cycle at timeline {current}"
                )));
            }
            let meta = self.timeline(current)?;
            chain.push(current);
            match meta.meta.fork_point {
                Some((parent, fork_seq)) => {
                    fork_seqs.push(fork_seq);
                    current = parent;
                }
                None => break,
            }
        }
        chain.reverse();
        fork_seqs.reverse();
        Ok(ForkChain {
            timelines: chain,
            fork_seqs,
        })
    }

    /// Walk at most `max_depth` parent links before returning the chain.
    fn fork_chain_bounded(
        &self,
        timeline_id: TimelineId,
        max_depth: usize,
        started: Instant,
        max_elapsed_micros: u64,
    ) -> Result<Vec<TimelineId>, CoreError> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = timeline_id;
        let mut depth = 0_usize;
        loop {
            #[cfg(test)]
            bounded_chain_delay_for_test();
            if let Some(error) = bounded_elapsed_error(started, max_elapsed_micros) {
                return Err(error);
            }
            if !visited.insert(current) {
                return Err(CoreError::Storage(format!(
                    "fork ancestry contains a cycle at timeline {current}"
                )));
            }
            let Some(state) = self.timelines.get(&current) else {
                return Err(CoreError::TimelineNotFound(current));
            };
            chain.push(current);
            match state.timeline.meta.fork_point {
                Some((parent, _)) => {
                    let next_depth = depth.saturating_add(1);
                    if next_depth > max_depth {
                        return Err(CoreError::ForkDepthTooLarge { depth: next_depth });
                    }
                    depth = next_depth;
                    current = parent;
                }
                None => break,
            }
        }
        chain.reverse();
        Ok(chain)
    }

    fn timeline_contains_geographic_evidence(
        &self,
        timeline: TimelineId,
    ) -> Result<bool, CoreError> {
        self.timeline(timeline)?;
        Ok(self.geographic_timelines.contains(&timeline))
    }

    fn ensure_generic_timeline_visibility(&self, timeline: TimelineId) -> Result<(), CoreError> {
        crate::ensure_generic_timeline_visibility(
            self.timeline_contains_geographic_evidence(timeline),
            timeline,
        )
    }

    fn ensure_admin_visibility(&self, timeline: TimelineId) -> Result<(), CoreError> {
        crate::ensure_generic_timeline_visibility(
            self.timeline_contains_geographic_evidence(timeline),
            timeline,
        )
    }

    fn with_erasure_fence<T>(
        &mut self,
        timeline: TimelineId,
        operation: ErasureProtectedOperationV1,
        mut effect: impl FnMut(&mut Self) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let gate = self.validated_erasure_gate()?;
        crate::with_validated_erasure_write_fence(&gate, timeline, operation, || effect(self))
    }

    fn with_erasure_read_fence<T>(
        &self,
        timeline: TimelineId,
        operation: ErasureProtectedOperationV1,
        mut effect: impl FnMut(&Self) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        let gate = self.validated_erasure_gate()?;
        let mut result = Err(CoreError::Storage(
            "erasure fence did not execute the protected operation".to_owned(),
        ));
        let mut run = || {
            result = effect(self);
        };
        let fenced = gate.with_fence(timeline, operation, &mut run);
        self.complete_erasure_read_fence(&gate, fenced, result)
    }

    fn with_erasure_read_filter<T>(
        &self,
        timeline: TimelineId,
        operation: ErasureProtectedOperationV1,
        mut effect: impl FnMut(&Self) -> Result<T, CoreError>,
    ) -> Result<Option<T>, CoreError> {
        let gate = self.validated_erasure_gate()?;
        let mut result = Err(CoreError::Storage(
            "erasure fence did not execute the protected operation".to_owned(),
        ));
        let mut run = || {
            result = effect(self);
        };
        let fenced = gate.with_fence(timeline, operation, &mut run);
        self.complete_erasure_read_filter(&gate, fenced, result)
    }

    fn validated_erasure_gate(&self) -> Result<Arc<ErasureContainmentGateV1>, CoreError> {
        let gate = self
            .erasure_gate
            .clone()
            .ok_or(CoreError::ErasureContainmentUnavailable)?;
        crate::validate_bound_erasure_inventory_generation(
            self.erasure_gate_bound,
            &gate,
            self.erasure_inventory_generation,
        )?;
        Ok(gate)
    }

    fn complete_erasure_read_fence<T>(
        &self,
        gate: &ErasureContainmentGateV1,
        fenced: Result<(), pos_core::ErasureContainmentErrorV1>,
        result: Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        crate::validate_bound_erasure_inventory_generation(
            self.erasure_gate_bound,
            gate,
            self.erasure_inventory_generation,
        )?;
        fenced.map_err(pos_core::store::erasure_containment_error)?;
        result
    }

    fn complete_erasure_read_filter<T>(
        &self,
        gate: &ErasureContainmentGateV1,
        fenced: Result<(), pos_core::ErasureContainmentErrorV1>,
        result: Result<T, CoreError>,
    ) -> Result<Option<T>, CoreError> {
        crate::validate_bound_erasure_inventory_generation(
            self.erasure_gate_bound,
            gate,
            self.erasure_inventory_generation,
        )?;
        match fenced {
            Ok(()) => result.map(Some),
            Err(pos_core::ErasureContainmentErrorV1::AccessFrozen) => Ok(None),
            Err(error) => Err(pos_core::store::erasure_containment_error(error)),
        }
    }

    fn visible_timeline_for_read(
        &self,
        candidate: &Timeline,
    ) -> Result<Option<Timeline>, CoreError> {
        let timeline = candidate.id();
        self.with_erasure_read_filter(timeline, ErasureProtectedOperationV1::Read, |store| {
            crate::generic_timeline_is_visible(
                store.timeline_contains_geographic_evidence(timeline),
            )
            .map(|visible| visible.then_some(candidate.clone()))
        })
        .map(Option::flatten)
    }

    fn timeline_visible_for_read(&self, timeline: TimelineId) -> Result<bool, CoreError> {
        self.with_erasure_read_filter(timeline, ErasureProtectedOperationV1::Read, |store| {
            crate::generic_timeline_is_visible(
                store.timeline_contains_geographic_evidence(timeline),
            )
        })
        .map(|visible| visible == Some(true))
    }

    fn count_visible_root_timeline_ids(
        &self,
        maximum: usize,
        timelines: impl IntoIterator<Item = TimelineId>,
    ) -> Result<usize, CoreError> {
        let stop_after = maximum.saturating_add(1);
        let mut count = 0;
        for timeline in timelines {
            if count >= stop_after {
                break;
            }
            if self.timeline_visible_for_read(timeline)? {
                count += 1;
            }
        }
        Ok(count)
    }

    fn append_visible(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        let logical_prefix = self.logical_prefix(timeline)?;
        self.append_visible_with_prefix(timeline, drafts, logical_prefix)
    }

    fn append_visible_with_prefix(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        logical_prefix: u64,
    ) -> Result<Vec<Event>, CoreError> {
        let committed = {
            let (timelines, hasher) = (&mut self.timelines, &self.hasher);
            mutable_state(timelines, timeline).and_then(|state| {
                drafts
                    .iter()
                    .map(|draft| Self::append_one_to_state(state, draft, hasher.as_ref()))
                    .collect::<Result<Vec<_>, _>>()
            })
        };
        committed
            .inspect(|events| {
                self.event_ids.extend(events.iter().map(|event| event.id));
            })
            .and_then(|events| {
                events
                    .into_iter()
                    .map(|event| Self::logical_event(logical_prefix, event))
                    .collect()
            })
    }

    fn fork_timeline_unchecked(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, CoreError> {
        let parent_head = self.logical_head_unchecked(parent)?;
        if at_seq > parent_head {
            return Err(CoreError::ForkBeyondHead {
                fork_seq: at_seq.as_u64(),
                head: parent_head.as_u64(),
            });
        }

        let meta = self
            .timelines
            .get(&parent)
            .and_then(|state| state.timeline.meta.owner)
            .map_or_else(
                || TimelineMeta::forked_from(parent, at_seq, name),
                |owner| TimelineMeta::forked_from_owned(parent, at_seq, name, owner),
            );
        let child = Timeline::new(meta);
        let fork_hash = self.compute_chain_hash_at_unchecked(parent, at_seq)?;
        self.timelines
            .insert(child.id(), TimelineState::new(child.clone(), fork_hash));
        Ok(child)
    }
}

impl ForkAdmissionAuthorityBootstrapPortV1 for MemoryStore {
    fn begin_fork_admission_initialize(
        &mut self,
        host_key: PublicKey,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionInitializeChallengeV1, ForkAdmissionAuthorityErrorV1> {
        begin_initialize(
            &mut self.fork_admission_authority,
            self.fork_admission_authority_enabled,
            host_key,
            policy_digest,
        )
    }

    fn finalize_fork_admission_initialize(
        &mut self,
        challenge: &ForkAdmissionInitializeChallengeV1,
        signature: &Signature,
    ) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1> {
        finalize_initialize(
            &mut self.fork_admission_authority,
            self.fork_admission_authority_enabled,
            challenge,
            signature,
        )
    }

    fn fork_admission_host_record(
        &self,
    ) -> Result<ForkAdmissionHostRecordV1, ForkAdmissionAuthorityErrorV1> {
        self.fork_admission_authority
            .host
            .ok_or(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    }

    fn begin_fork_admission_open(
        &mut self,
        host_key: PublicKey,
        policy_digest: Hash,
    ) -> Result<ForkAdmissionOpenChallengeV1, ForkAdmissionAuthorityErrorV1> {
        begin_open(
            &mut self.fork_admission_authority,
            self.fork_admission_authority_enabled,
            host_key,
            policy_digest,
        )
    }

    fn finalize_fork_admission_open(
        &mut self,
        challenge: &ForkAdmissionOpenChallengeV1,
        signature: &Signature,
    ) -> Result<ForkAdmissionAuthoritySessionV1, ForkAdmissionAuthorityErrorV1> {
        finalize_open(
            &mut self.fork_admission_authority,
            self.fork_admission_authority_enabled,
            challenge,
            signature,
        )
    }

    fn advance_fork_admission_wall_fence(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<(), ForkAdmissionAuthorityErrorV1> {
        advance_wall_fence(
            &mut self.fork_admission_authority,
            self.fork_admission_authority_enabled,
            session,
        )
    }
}

impl ForkAdmissionAuthorityPortV1 for MemoryStore {
    fn execute_fork_admission_command(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &pos_core::fork_authentication::ForkAuthenticationPolicyV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        let verified = self.verify_fork_admission_command(session, policy, command)?;
        let requires_permit = self.erasure_topology_requires_permit;
        let gate = self.validated_erasure_gate();
        with_unfenced_fork_containment(&verified, requires_permit, gate, |containment| {
            self.execute_verified_fork_admission(session, verified.clone(), containment)
        })
    }

    fn execute_fork_admission_command_in_topology_transition(
        &mut self,
        context: &pos_core::ErasureAdmittedForkContextV1<'_>,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &pos_core::fork_authentication::ForkAuthenticationPolicyV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        let verified = self.verify_fork_admission_command(session, policy, command)?;
        let target = verified
            .fork_target()
            .ok_or(pos_core::ForkAdmissionErrorV1::InvalidRequest)?;
        let containment = admitted_fork_context_containment(
            context,
            self.validated_erasure_gate().ok().as_deref(),
            self.erasure_topology_store_binding.as_ref(),
            target,
        );
        let result = self.execute_verified_fork_admission(session, verified, containment);
        if admitted_fork_may_have_changed_topology(&result) {
            self.erasure_inventory_generation = None;
        }
        result
    }

    fn recover_fork_admission_command(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        proof: &ForkAdmissionRecoveryProofV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        let host = self
            .fork_admission_authority
            .host
            .ok_or(pos_core::ForkAdmissionErrorV1::AuthorityUninitialized)?;
        let query = verify_recovery_proof(
            session,
            self.fork_admission_authority.session_identity,
            host,
            proof,
        )?;
        let row = self
            .fork_admission_operations
            .get(&(query.kind, query.operation_id))
            .ok_or(pos_core::ForkAdmissionErrorV1::OperationMissing)?;
        self.stored_fork_admission_result(row)
    }
}

impl ForkAdmissionDeliveryJournalPortV1 for MemoryStore {
    fn claim_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
    ) -> Result<ForkDeliveryClaimOutcomeV1, ForkDeliveryJournalErrorV1> {
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkDeliveryJournalErrorV1::Corrupt);
        }
        let tuple = tuple.revalidate()?;
        if let Some(row) = self.fork_delivery_journal.get(&tuple.host_request_id) {
            if row.tuple != tuple {
                return Err(ForkDeliveryJournalErrorV1::Conflict);
            }
            return Ok(match row.state {
                ForkDeliveryStateV1::Pending => ForkDeliveryClaimOutcomeV1::Busy,
                state => ForkDeliveryClaimOutcomeV1::Reconcile(
                    ForkDeliveryClaimV1 {
                        tuple,
                        owner_fence: row.owner_fence,
                    },
                    state,
                ),
            });
        }
        if self
            .fork_delivery_journal
            .values()
            .any(|row| row.tuple.kind == tuple.kind && row.tuple.operation_id == tuple.operation_id)
        {
            return Err(ForkDeliveryJournalErrorV1::Conflict);
        }
        let owner_fence = self
            .fork_delivery_last_fence
            .checked_add(1)
            .ok_or(ForkDeliveryJournalErrorV1::StorageIndeterminate)?;
        self.fork_delivery_last_fence = owner_fence;
        let claim = ForkDeliveryClaimV1 { tuple, owner_fence };
        self.fork_delivery_journal.insert(
            tuple.host_request_id,
            ForkDeliveryRowV1 {
                tuple,
                state: ForkDeliveryStateV1::Pending,
                owner_fence,
            },
        );
        Ok(ForkDeliveryClaimOutcomeV1::Owner(claim))
    }

    fn cancel_pending_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        claim: ForkDeliveryClaimV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1> {
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkDeliveryJournalErrorV1::Corrupt);
        }
        self.fork_delivery_journal
            .get(&claim.tuple.host_request_id)
            .filter(|row| row.matches_claim(claim, ForkDeliveryStateV1::Pending))
            .ok_or(ForkDeliveryJournalErrorV1::Fenced)?;
        self.fork_delivery_journal
            .remove(&claim.tuple.host_request_id);
        Ok(())
    }

    fn execute_claimed_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &pos_core::ForkAuthenticationPolicyV1,
        claim: ForkDeliveryClaimV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1> {
        // Same order as the SQLite adapter: authenticate the command, bind it
        // to the claimed tuple, then check the owner fence.
        let host = self
            .fork_admission_authority
            .host
            .ok_or(ForkDeliveryJournalErrorV1::Corrupt)?;
        let verified = verify_command(
            session,
            self.fork_admission_authority.session_identity,
            host,
            policy,
            command,
        )
        .map_err(|_| ForkDeliveryJournalErrorV1::Corrupt)?;
        if verified.kind() != claim.tuple.kind
            || verified.operation_id() != claim.tuple.operation_id
        {
            return Err(ForkDeliveryJournalErrorV1::Conflict);
        }
        self.fork_delivery_journal
            .get(&claim.tuple.host_request_id)
            .filter(|row| row.matches_claim(claim, ForkDeliveryStateV1::Pending))
            .ok_or(ForkDeliveryJournalErrorV1::Fenced)?;
        let execution =
            fork_delivery_execution(self.execute_fork_admission_command(session, policy, command));
        self.record_fork_delivery_disposition(claim, &execution);
        Ok(execution)
    }

    fn execute_claimed_fork_delivery_in_topology_transition(
        &mut self,
        context: &pos_core::ErasureAdmittedForkContextV1<'_>,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &pos_core::ForkAuthenticationPolicyV1,
        claim: ForkDeliveryClaimV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<ForkDeliveryExecutionV1, ForkDeliveryJournalErrorV1> {
        // Same pre-write order as the SQLite adapter (ADR-109 r9 Decision 2):
        // authenticate the command, then bind it to the claimed FCC1 tuple. A
        // POC1 is not a topology mutation and is refused as Conflict.
        let host = self.live_fork_delivery_host(session)?;
        let verified = verify_command(
            session,
            self.fork_admission_authority.session_identity,
            host,
            policy,
            command,
        )
        .map_err(|_| ForkDeliveryJournalErrorV1::Corrupt)?;
        let target = verified
            .fork_target()
            .filter(|_| {
                verified.kind() == claim.tuple.kind
                    && verified.operation_id() == claim.tuple.operation_id
            })
            .ok_or(ForkDeliveryJournalErrorV1::Conflict)?;
        // The exclusive borrow is the write boundary; a changed owner writes
        // nothing.
        self.fork_delivery_journal
            .get(&claim.tuple.host_request_id)
            .filter(|row| row.matches_claim(claim, ForkDeliveryStateV1::Pending))
            .ok_or(ForkDeliveryJournalErrorV1::Fenced)?;
        let containment = admitted_fork_context_containment(
            context,
            self.validated_erasure_gate().ok().as_deref(),
            self.erasure_topology_store_binding.as_ref(),
            target,
        );
        let execution = fork_delivery_execution(self.execute_verified_fork_admission(
            session,
            verified,
            containment,
        ));
        if matches!(execution, ForkDeliveryExecutionV1::Rejected(_)) {
            // The rejected FAC1 was staged but never applied, so no FAC1 or
            // topology write survives; only the Pending deletion remains.
            let Ok(()) =
                context.roll_back_write_boundary(|| Ok::<(), std::convert::Infallible>(()));
        }
        self.record_fork_delivery_disposition(claim, &execution);
        // As in this adapter's r3 permit method, a possible topology change
        // alone invalidates the captured generation: the exclusive borrow
        // applies a FAC1 only when it commits, so no outcome here can have
        // opened and rolled back a partial write that `nothing_written` would
        // need to rule out.
        if fork_delivery_may_have_changed_topology(Ok(&execution)) {
            self.erasure_inventory_generation = None;
        }
        Ok(execution)
    }

    fn recover_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
        proof: &ForkAdmissionRecoveryProofV1,
        current_principal_digest: Hash,
    ) -> Result<ForkAdmissionOperationResultV1, ForkDeliveryJournalErrorV1> {
        let host = self.live_fork_delivery_host(session)?;
        if current_principal_digest == Hash::zero() {
            return Err(ForkDeliveryJournalErrorV1::InvalidTuple);
        }
        let row = self
            .fork_delivery_journal
            .get(&tuple.host_request_id)
            .copied()
            .ok_or(ForkDeliveryJournalErrorV1::Corrupt)?;
        if row.tuple != tuple {
            return Err(ForkDeliveryJournalErrorV1::Conflict);
        }
        if row.state == ForkDeliveryStateV1::Pending {
            return Err(ForkDeliveryJournalErrorV1::Fenced);
        }
        let query = verify_recovery_proof(
            session,
            self.fork_admission_authority.session_identity,
            host,
            proof,
        )
        .map_err(|_| ForkDeliveryJournalErrorV1::Corrupt)?;
        if query.kind != tuple.kind || query.operation_id != tuple.operation_id {
            return Err(ForkDeliveryJournalErrorV1::Conflict);
        }
        let result = self
            .recover_fork_admission_command(session, proof)
            .map_err(|_| ForkDeliveryJournalErrorV1::Corrupt)?;
        if !self.delivery_result_matches_principal(&result, current_principal_digest) {
            return Err(ForkDeliveryJournalErrorV1::Corrupt);
        }
        Ok(result)
    }

    fn mark_fork_delivery_uncertain(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        claim: ForkDeliveryClaimV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1> {
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkDeliveryJournalErrorV1::Corrupt);
        }
        // A committed FAC1 already recorded Uncertain; this call is only the
        // owner-fence check that the committed owner still holds the tuple.
        self.fork_delivery_journal
            .get(&claim.tuple.host_request_id)
            .filter(|row| row.matches_claim(claim, ForkDeliveryStateV1::Uncertain))
            .map(|_| ())
            .ok_or(ForkDeliveryJournalErrorV1::Fenced)
    }

    fn mark_fork_delivery_delivered(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        claim: ForkDeliveryClaimV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1> {
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkDeliveryJournalErrorV1::Corrupt);
        }
        self.fork_delivery_journal
            .get_mut(&claim.tuple.host_request_id)
            .filter(|row| row.matches_claim(claim, ForkDeliveryStateV1::Uncertain))
            .map(|row| row.state = ForkDeliveryStateV1::Delivered)
            .ok_or(ForkDeliveryJournalErrorV1::Fenced)
    }

    fn reconcile_fork_delivery_journal(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<Vec<ForkDeliveryTupleV1>, ForkDeliveryJournalErrorV1> {
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkDeliveryJournalErrorV1::Corrupt);
        }
        Ok(self
            .fork_delivery_journal
            .values()
            .filter(|row| row.state != ForkDeliveryStateV1::Delivered)
            .map(|row| row.tuple)
            .collect())
    }

    fn reconcile_fork_delivery_startup(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
        proof: &ForkAdmissionRecoveryProofV1,
    ) -> Result<ForkDeliveryStartupOutcomeV1, ForkDeliveryJournalErrorV1> {
        // Same order as the SQLite adapter: verify FRP1 before the row.
        let host = self.live_fork_delivery_host(session)?;
        let query = verify_recovery_proof(
            session,
            self.fork_admission_authority.session_identity,
            host,
            proof,
        )
        .map_err(|_| ForkDeliveryJournalErrorV1::Corrupt)?;
        if query.kind != tuple.kind || query.operation_id != tuple.operation_id {
            return Err(ForkDeliveryJournalErrorV1::Conflict);
        }
        let row = self
            .fork_delivery_journal
            .get(&tuple.host_request_id)
            .copied()
            .ok_or(ForkDeliveryJournalErrorV1::Corrupt)?;
        if row.tuple != tuple || row.state == ForkDeliveryStateV1::Delivered {
            return Err(ForkDeliveryJournalErrorV1::Fenced);
        }
        match self.recover_fork_admission_command(session, proof) {
            Ok(_) => {
                self.fork_delivery_journal.insert(
                    tuple.host_request_id,
                    ForkDeliveryRowV1 {
                        tuple,
                        state: ForkDeliveryStateV1::Uncertain,
                        owner_fence: row.owner_fence,
                    },
                );
                Ok(ForkDeliveryStartupOutcomeV1::RetainedUncertain)
            }
            Err(pos_core::ForkAdmissionErrorV1::OperationMissing)
                if row.state == ForkDeliveryStateV1::Pending =>
            {
                self.fork_delivery_journal.remove(&tuple.host_request_id);
                Ok(ForkDeliveryStartupOutcomeV1::ReleasedPending)
            }
            Err(_) => Err(ForkDeliveryJournalErrorV1::Corrupt),
        }
    }

    fn purge_expired_fork_delivery(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
    ) -> Result<(), ForkDeliveryJournalErrorV1> {
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkDeliveryJournalErrorV1::Corrupt);
        }
        // Same as the SQLite exact-row DELETE: any non-exact or absent row is Fenced.
        self.fork_delivery_journal
            .get(&tuple.host_request_id)
            .filter(|row| row.tuple == tuple && row.state == ForkDeliveryStateV1::Delivered)
            .ok_or(ForkDeliveryJournalErrorV1::Fenced)?;
        self.fork_delivery_journal.remove(&tuple.host_request_id);
        Ok(())
    }
}

impl MemoryStore {
    /// Apply one FAC1 outcome to its claimed tuple: a definite rejection
    /// deletes Pending, and every other outcome retains the tuple Uncertain.
    fn record_fork_delivery_disposition(
        &mut self,
        claim: ForkDeliveryClaimV1,
        execution: &ForkDeliveryExecutionV1,
    ) {
        if matches!(execution, ForkDeliveryExecutionV1::Rejected(_)) {
            self.fork_delivery_journal
                .remove(&claim.tuple.host_request_id);
        } else {
            self.fork_delivery_journal.insert(
                claim.tuple.host_request_id,
                ForkDeliveryRowV1 {
                    tuple: claim.tuple,
                    state: ForkDeliveryStateV1::Uncertain,
                    owner_fence: claim.owner_fence,
                },
            );
        }
    }

    /// Returns the live FAH1 host, or `Corrupt` for a stale session.
    fn live_fork_delivery_host(
        &self,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<ForkAdmissionHostRecordV1, ForkDeliveryJournalErrorV1> {
        self.fork_admission_authority
            .host
            .filter(|_| validate_live_session(&self.fork_admission_authority, session))
            .ok_or(ForkDeliveryJournalErrorV1::Corrupt)
    }

    fn delivery_result_matches_principal(
        &self,
        result: &ForkAdmissionOperationResultV1,
        principal_digest: Hash,
    ) -> bool {
        match result {
            ForkAdmissionOperationResultV1::PrincipalOwner(binding) => {
                binding.input().principal_digest == principal_digest
            }
            ForkAdmissionOperationResultV1::Fork(receipt) => self
                .fork_admissions
                .get(&receipt.child_id)
                .and_then(|admission| {
                    self.principal_owner_binding_by_digest(
                        admission.input().principal_owner_binding_digest,
                    )
                })
                .is_some_and(|binding| binding.input().principal_digest == principal_digest),
        }
    }
}

impl MemoryStore {
    /// Rebuild and validate the complete FAR1/FCS1/FCT1/FCR1 closure for one child.
    fn classified_authority_graph(
        &self,
        child_timeline_id: TimelineId,
    ) -> Result<
        (
            ForkAdmissionRecordV1,
            ForkClassifierTableV1,
            ForkClassifierRegistrationV1,
        ),
        ForkEventAuthorityErrorV1,
    > {
        let admission = self.validated_local_fork_admission(child_timeline_id)?;
        let table = self
            .fork_classifier_tables
            .get(&child_timeline_id)
            .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)?;
        let mut registrations = self
            .fork_classifier_registrations
            .values()
            .filter(|registration| registration.input().child_timeline_id == child_timeline_id);
        let registration = registrations
            .next()
            .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)?;
        if registrations.next().is_some() {
            return Err(ForkEventAuthorityErrorV1::CorruptAuthority);
        }
        let source = self
            .fork_classifier_sources
            .get(&(
                table.input().room_revision_descriptor_hash,
                table.input().registrar_identifier.clone(),
            ))
            .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)?;
        (table.input().fork_admission_digest == admission.digest()
            && table.input().room_revision_descriptor_hash
                == admission.input().room_revision_descriptor_hash
            && source.input().room_revision_descriptor_hash
                == table.input().room_revision_descriptor_hash
            && source.input().registrar_identifier == table.input().registrar_identifier
            && table.input().source_configuration_revision_digest == source.digest()
            && table.input().routes == source.input().routes
            && registration.input().fork_admission_digest == admission.digest()
            && registration.input().room_revision_descriptor_hash
                == admission.input().room_revision_descriptor_hash
            && registration.input().classifier_revision_digest == table.digest())
        .then(|| (admission, table.clone(), registration.clone()))
        .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)
    }

    /// Validate the child's authority closure against digests retained by evidence.
    fn validate_classified_authority_graph(
        &self,
        child_timeline_id: TimelineId,
        fork_admission_digest: Hash,
        classifier_revision_digest: Hash,
    ) -> Result<(ForkAdmissionRecordV1, ForkClassifierTableV1), ForkEventAuthorityErrorV1> {
        self.classified_authority_graph(child_timeline_id)
            .and_then(|(admission, table, _)| {
                (admission.digest() == fork_admission_digest
                    && table.digest() == classifier_revision_digest)
                    .then_some((admission, table))
                    .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)
            })
    }

    fn validate_classified_permit(
        &self,
        permit: &ForkAppendSourcePermitV1,
    ) -> Result<ForkClassifierTableV1, ForkEventAuthorityErrorV1> {
        self.classified_authority_graph(permit.child_timeline_id())
            .and_then(|(admission, table, registration)| {
                permit
                    .names_scope(&admission, &table, &registration)
                    .then_some(table)
                    .ok_or(ForkEventAuthorityErrorV1::Unauthenticated)
            })
    }

    /// Read the logical Timeline Event one FOP1 binds, as `SQLite` reads its row.
    ///
    /// ADR-105 r6 R6.9: the committed Timeline Event is what every adapter
    /// validates and returns; an Event with another id is corrupt authority.
    fn committed_classified_event(
        &self,
        operation: &ForkAppendOperationV1,
    ) -> Result<Event, ForkEventAuthorityErrorV1> {
        let input = operation.input();
        self.committed_logical_event(input.child_timeline_id, input.logical_seq)
            .filter(|event| event.id == input.event_id)
            .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)
    }

    /// The child's committed Event at one logical sequence, in logical form.
    ///
    /// A sequence inside the inherited prefix saturates to local sequence 0,
    /// which no committed child Event carries.
    fn committed_logical_event(
        &self,
        child_timeline_id: TimelineId,
        logical_seq: u64,
    ) -> Option<Event> {
        let state = self.timelines.get(&child_timeline_id)?;
        let prefix = state
            .timeline
            .meta
            .fork_point
            .map_or(0, |(_, fork)| fork.as_u64());
        let local_seq = logical_seq.saturating_sub(prefix);
        let event = state
            .events
            .binary_search_by_key(&local_seq, |event| event.seq.as_u64())
            .ok()
            .and_then(|index| state.events.get(index))?;
        Self::logical_event(prefix, event.clone()).ok()
    }

    fn validate_classified_provenance(
        &self,
        operation: &ForkAppendOperationV1,
    ) -> Result<Event, ForkEventAuthorityErrorV1> {
        let input = operation.input();
        self.validate_classified_authority_graph(
            input.child_timeline_id,
            input.fork_admission_digest,
            input.classifier_revision_digest,
        )
        .and_then(|(_, table)| {
            self.committed_classified_event(operation)
                .map(|event| (table, event))
        })
        .and_then(|(table, event)| {
            self.validate_classified_records(operation, &event, &table)
                .map(|_| event)
        })
    }

    /// Require the logical Event, EOR1, and FIA1 exactly bound by one FOP1.
    fn validate_classified_records(
        &self,
        operation: &ForkAppendOperationV1,
        event: &Event,
        table: &ForkClassifierTableV1,
    ) -> Result<(EventOriginRecordV1, Option<ForkInterventionAdmissionV1>), ForkEventAuthorityErrorV1>
    {
        let input = operation.input();
        let intervention = self.fork_intervention_admissions.get(&event.id);
        // A missing EOR1 and an unclassifiable FOP1 source are both corrupt
        // authority, exactly like any field mismatch below.
        self.fork_event_origins
            .get(&event.id)
            .zip(
                ForkEventClassifierV1::from_table(table)
                    .classify_identity(&input.source)
                    .ok(),
            )
            .filter(|(origin, classification)| {
                let (expected_origin, expected_intervention) =
                    operation.expected_provenance(table, *classification);
                event.id == input.event_id
                    && event.seq.as_u64() == input.logical_seq
                    && classified_event_matches_operation(event, operation)
                    && **origin == expected_origin
                    && origin.digest() == input.event_origin_digest
                    && intervention == expected_intervention.as_ref()
                    && intervention.map(ForkInterventionAdmissionV1::digest)
                        == input.intervention_admission_digest
            })
            .map(|(origin, _)| (origin.clone(), intervention.cloned()))
            .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)
    }

    fn validated_local_fork_admission(
        &self,
        child_timeline_id: TimelineId,
    ) -> Result<ForkAdmissionRecordV1, ForkEventAuthorityErrorV1> {
        // Every missing, foreign, or mismatched FAR1/FCC1 row is corrupt
        // authority; the committed Fork receipt must name exactly this FAR1.
        self.fork_admissions
            .get(&child_timeline_id)
            .filter(|admission| {
                admission.input().child_timeline_id == child_timeline_id
                    && admission.input().origin == ForkAttributionOriginV1::Local
            })
            .and_then(|admission| {
                let expected = ForkAdmissionOperationResultV1::Fork(ForkAdmissionReceiptV1 {
                    child_id: child_timeline_id,
                    admission_digest: admission.digest(),
                });
                self.fork_admission_operations
                    .get(&(
                        ForkAdmissionOperationKindV1::Fork,
                        admission.input().operation_id,
                    ))
                    .and_then(|row| self.stored_fork_admission_result(row).ok())
                    .filter(|result| *result == expected)
                    .map(|_| admission.clone())
            })
            .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)
    }
}

impl ForkEventProvenanceAuthorityPortV1 for MemoryStore {
    fn register_classifier(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        permit: &ForkClassifierRegistrarPermitV1,
        operation_id: Hash,
        child_timeline_id: TimelineId,
    ) -> Result<ForkClassifierRegistrationReceiptV1, ForkEventAuthorityErrorV1> {
        let source = permit.source();
        if !permit.authorizes(session, child_timeline_id) {
            return Err(ForkEventAuthorityErrorV1::Unauthenticated);
        }
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkEventAuthorityErrorV1::Unauthenticated);
        }
        let admission = self
            .validated_local_fork_admission(child_timeline_id)
            .and_then(|admission| {
                permitted_fork_admission(permit.fork_admission_digest(), admission)
            })?;
        if admission.input().room_revision_descriptor_hash
            != source.input().room_revision_descriptor_hash
        {
            return Err(ForkEventAuthorityErrorV1::Conflict);
        }
        let table = ForkClassifierTableV1::for_admitted_source(&admission, source);
        let registration = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
            operation_id,
            child_timeline_id,
            fork_admission_digest: admission.digest(),
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            classifier_revision_digest: table.digest(),
        })
        .map_err(|_| ForkEventAuthorityErrorV1::InvalidRequest)?;
        let receipt = ForkClassifierRegistrationReceiptV1 {
            child_timeline_id,
            classifier_revision_digest: table.digest(),
            registration_digest: registration.digest(),
        };
        if let Some(existing) = self.fork_classifier_registrations.get(&operation_id) {
            if existing != &registration {
                return Err(ForkEventAuthorityErrorV1::Conflict);
            }
            return self
                .validate_classified_authority_graph(
                    child_timeline_id,
                    admission.digest(),
                    table.digest(),
                )
                .map(|_| receipt);
        }
        if !self.state(child_timeline_id).events.is_empty()
            || self.fork_classifier_tables.contains_key(&child_timeline_id)
        {
            return Err(ForkEventAuthorityErrorV1::Conflict);
        }
        let key = (
            source.input().room_revision_descriptor_hash,
            source.input().registrar_identifier.clone(),
        );
        match self.fork_classifier_sources.get(&key) {
            Some(existing) if existing != source => {
                return Err(ForkEventAuthorityErrorV1::Conflict)
            }
            Some(_) => {}
            None => {
                self.fork_classifier_sources.insert(key, source.clone());
            }
        }
        self.fork_classifier_tables.insert(child_timeline_id, table);
        self.fork_classifier_registrations
            .insert(operation_id, registration);
        Ok(receipt)
    }

    fn append_classified(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        permit: &ForkAppendSourcePermitV1,
        operation_id: Hash,
        draft: EventDraft,
    ) -> Result<ForkClassifiedAppendReceiptV1, ForkEventAuthorityErrorV1> {
        let source = permit.source();
        let child_timeline_id = permit.child_timeline_id();
        if !permit.is_live_for(session) {
            return Err(ForkEventAuthorityErrorV1::Unauthenticated);
        }
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkEventAuthorityErrorV1::Unauthenticated);
        }
        let request = fork_append_request(operation_id, child_timeline_id, source, &draft)?;
        let table = self.validate_classified_permit(permit)?;
        if let Some(operation) = self.fork_append_operations.get(&operation_id) {
            if operation.input().request_digest != request.digest() {
                return Err(ForkEventAuthorityErrorV1::Conflict);
            }
            return self.validate_classified_provenance(operation).map(|event| {
                ForkClassifiedAppendReceiptV1 {
                    event,
                    operation: operation.clone(),
                }
            });
        }
        let classification = ForkEventClassifierV1::from_table(&table)
            .classify_identity(source)
            .map_err(|_| ForkEventAuthorityErrorV1::ClassifierRejected)?;
        let hasher: &dyn Hasher = self.hasher.as_ref();
        // Every fallible step precedes the first mutation, matching SQLite's
        // all-or-nothing transaction.
        let (event, provenance) = self
            .timelines
            .get_mut(&child_timeline_id)
            .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)
            .and_then(|state| {
                let prefix = state
                    .timeline
                    .meta
                    .fork_point
                    .map_or(0, |(_, fork)| fork.as_u64());
                Self::prepare_one_for_state(state, &draft, hasher)
                    .and_then(|(local_event, chain_head)| {
                        Self::logical_event(prefix, local_event.clone())
                            .map(|event| (local_event, chain_head, event))
                    })
                    .map_err(|_| ForkEventAuthorityErrorV1::StorageIndeterminate)
                    .and_then(|(local_event, chain_head, event)| {
                        ForkClassifiedProvenanceV1::derive(
                            &request,
                            &table,
                            classification,
                            ForkClassifiedEventV1 {
                                event_id: event.id,
                                logical_seq: event.seq.as_u64(),
                                wall_time: event.wall_time,
                                payload_hash: event.payload_hash,
                            },
                        )
                        .map_err(|_| ForkEventAuthorityErrorV1::InvalidRequest)
                        .map(|provenance| {
                            Self::commit_prepared_to_state(state, local_event, chain_head);
                            (event, provenance)
                        })
                    })
            })?;
        self.event_ids.insert(event.id);
        self.fork_event_origins.insert(event.id, provenance.origin);
        if let Some(intervention) = provenance.intervention {
            self.fork_intervention_admissions
                .insert(event.id, intervention);
        }
        self.fork_append_operations
            .insert(operation_id, provenance.operation.clone());
        Ok(ForkClassifiedAppendReceiptV1 {
            event,
            operation: provenance.operation,
        })
    }

    fn recover_classified_append(
        &self,
        session: &ForkAdmissionAuthoritySessionV1,
        permit: &ForkAppendSourcePermitV1,
        operation_id: Hash,
        draft: &EventDraft,
    ) -> Result<Option<ForkClassifiedAppendReceiptV1>, ForkEventAuthorityErrorV1> {
        if !permit.is_live_for(session) {
            return Err(ForkEventAuthorityErrorV1::Unauthenticated);
        }
        if !validate_live_session(&self.fork_admission_authority, session) {
            return Err(ForkEventAuthorityErrorV1::Unauthenticated);
        }
        self.validate_classified_permit(permit)?;
        let Some(operation) = self.fork_append_operations.get(&operation_id) else {
            return Ok(None);
        };
        recover_classified_operation(
            |operation| self.validate_classified_provenance(operation),
            operation.clone(),
            permit,
            operation_id,
            draft,
        )
    }

    fn read_fork_event_suffix(
        &self,
        child_timeline_id: TimelineId,
        from_logical_seq: u64,
    ) -> Result<
        Vec<(
            EventOriginRecordV1,
            Option<ForkInterventionAdmissionV1>,
            ForkAppendOperationV1,
        )>,
        ForkEventAuthorityErrorV1,
    > {
        let prefix = self
            .logical_prefix(child_timeline_id)
            .map_err(|_| ForkEventAuthorityErrorV1::CorruptAuthority)?;
        let events = &self.state(child_timeline_id).events;
        let logical_seqs = events
            .iter()
            .filter_map(|event| {
                prefix
                    .checked_add(event.seq.as_u64())
                    .map(|logical_seq| (event.id, logical_seq))
            })
            .collect::<HashMap<_, _>>();
        let anchored =
            |event_id: EventId, logical_seq: u64| logical_seqs.get(&event_id) == Some(&logical_seq);
        let orphaned_operation = self.fork_append_operations.values().any(|operation| {
            operation.input().child_timeline_id == child_timeline_id
                && !anchored(operation.input().event_id, operation.input().logical_seq)
        });
        let orphaned_origin = self.fork_event_origins.values().any(|origin| {
            origin.input().fork_timeline_id == child_timeline_id
                && !anchored(origin.input().event_id, origin.input().logical_seq)
        });
        let orphaned_intervention = self.fork_intervention_admissions.values().any(|record| {
            record.input().fork_timeline_id == child_timeline_id
                && !anchored(record.input().event_id, record.input().logical_seq)
        });
        if orphaned_operation || orphaned_origin || orphaned_intervention {
            return Err(ForkEventAuthorityErrorV1::CorruptAuthority);
        }
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let mut operations = HashMap::with_capacity(logical_seqs.len());
        for operation in self.fork_append_operations.values() {
            if logical_seqs.contains_key(&operation.input().event_id)
                && operations
                    .insert(operation.input().event_id, operation)
                    .is_some()
            {
                return Err(ForkEventAuthorityErrorV1::CorruptAuthority);
            }
        }
        let (admission, table, _) = self.classified_authority_graph(child_timeline_id)?;
        events
            .iter()
            .filter_map(|event| {
                prefix
                    .checked_add(event.seq.as_u64())
                    .filter(|logical_seq| *logical_seq >= from_logical_seq)
                    .map(|logical_seq| (event, logical_seq))
            })
            .map(|(event, logical_seq)| {
                let operation = operations
                    .get(&event.id)
                    .copied()
                    .ok_or(ForkEventAuthorityErrorV1::CorruptAuthority)?;
                if operation.input().logical_seq != logical_seq
                    || operation.input().fork_admission_digest != admission.digest()
                    || operation.input().classifier_revision_digest != table.digest()
                {
                    return Err(ForkEventAuthorityErrorV1::CorruptAuthority);
                }
                let committed = Event {
                    seq: Seq::from_u64(logical_seq),
                    ..event.clone()
                };
                self.validate_classified_records(operation, &committed, &table)
                    .map(|(origin, intervention)| (origin, intervention, operation.clone()))
            })
            .collect()
    }
}

impl crate::fork_event_authority::ForkEventPermitIssuerPortV1 for MemoryStore {
    fn read_validated_local_fork_admission(
        &self,
        child_timeline_id: TimelineId,
    ) -> Result<ForkAdmissionRecordV1, ForkEventAuthorityErrorV1> {
        self.validated_local_fork_admission(child_timeline_id)
    }

    fn preflight_fork_classifier_profile(
        &self,
        profile_sources: &[ForkClassifierSourceV1],
    ) -> Result<(), ForkEventAuthorityErrorV1> {
        preflight_classifier_sources(self.fork_classifier_sources.values(), profile_sources)
    }

    fn issue_classifier_registrar_permit(
        &self,
        issuer: &crate::fork_event_authority::ForkEventPermitIssuerV1,
        session: &ForkAdmissionAuthoritySessionV1,
        child_timeline_id: TimelineId,
        source: ForkClassifierSourceV1,
    ) -> Result<ForkClassifierRegistrarPermitV1, ForkEventAuthorityErrorV1> {
        issuer
            .authorize(session, || self.live_fork_event_session(session))
            .and_then(|()| self.validated_local_fork_admission(child_timeline_id))
            .and_then(|admission| issuer.registrar_permit(&admission, source))
    }

    fn issue_append_source_permit(
        &self,
        issuer: &crate::fork_event_authority::ForkEventPermitIssuerV1,
        session: &ForkAdmissionAuthoritySessionV1,
        child_timeline_id: TimelineId,
        selected_source: &ForkClassifierSourceV1,
        source: ForkAppendSourceIdentityV1,
    ) -> Result<ForkAppendSourcePermitV1, ForkEventAuthorityErrorV1> {
        issuer
            .authorize(session, || self.live_fork_event_session(session))
            .and_then(|()| issuer.live_source_scope(&source))
            .and_then(|scope| {
                self.classified_authority_graph(child_timeline_id)
                    .and_then(|graph| issuer.append_permit(scope, graph, selected_source, source))
            })
    }
}

impl MemoryStore {
    /// The `MemoryStore` live-session check used by permit issuance.
    fn live_fork_event_session(
        &self,
        session: &ForkAdmissionAuthoritySessionV1,
    ) -> Result<(), ForkEventAuthorityErrorV1> {
        validate_live_session(&self.fork_admission_authority, session)
            .then_some(())
            .ok_or(ForkEventAuthorityErrorV1::Unauthenticated)
    }
}

impl MemoryStore {
    /// Read the admitted Fork's immutable `FAR1`.
    fn fork_publication_admission(
        &self,
        child_timeline_id: TimelineId,
    ) -> PublicationSourceResultV1<ForkAdmissionRecordV1> {
        self.fork_admissions
            .get(&child_timeline_id)
            .cloned()
            .ok_or(PublicationSourceErrorV1::Invalid)
    }

    /// Read the admitted child's classified suffix after its parent cut.
    fn fork_publication_suffix(
        &self,
        child_timeline_id: TimelineId,
        parent_logical_head: PublicationSourceResultV1<u64>,
    ) -> PublicationSourceResultV1<PublicationSuffixV1> {
        parent_logical_head.and_then(|parent_logical_head| {
            self.read_fork_event_suffix(child_timeline_id, parent_logical_head.saturating_add(1))
                .map_err(PublicationSourceErrorV1::from)
        })
    }

    /// Whether any stored `FPO1`, `FPB1`, or `FPA1` already carries
    /// `record_id`.
    fn fork_publication_record_is_present(&self, record_id: Hash) -> bool {
        self.fork_publication_artifacts.contains_key(&record_id)
            || self
                .fork_publication_operations
                .values()
                .any(|row| row.input().signed_manifest_record_id == record_id)
            || self
                .fork_publication_bindings
                .values()
                .any(|row| row.input().signed_manifest_record_id == record_id)
    }

    /// Read the authoritative Fork provenance sources for one new issuance.
    fn fork_publication_sources(
        &self,
        request: &ForkManifestPublicationRequestV1,
    ) -> Result<PublicationSourcesV1, ForkManifestPublicationErrorV1> {
        let child = request.child_timeline_id;
        let admission = self.fork_publication_admission(child);
        let suffix = self.fork_publication_suffix(child, publication_parent_head(&admission));
        let head_and_chain = self
            .logical_head_unchecked(child)
            .and_then(|head| {
                self.compute_chain_hash_at_unchecked(child, head)
                    .map(|chain| (head.as_u64(), chain))
            })
            .map_err(PublicationSourceErrorV1::from);
        publication_sources(request, admission, head_and_chain, suffix)
    }

    /// ADR-099 preflight for an absent `FPO1`, then held authorization,
    /// provenance, one signer call, and the post-signing check that no
    /// `FPO1`, `FPB1`, or `FPA1` already carries the new record ID.
    fn sign_new_fork_publication<E, F>(
        &self,
        request: &ForkManifestPublicationRequestV1,
        key: &(TimelineId, u64),
        sign: F,
    ) -> Result<PublicationGraphV1, ForkManifestPublicationErrorV1>
    where
        F: FnOnce(&HeldRegistryAuthorizationV1, &[u8]) -> Result<Signature, E>,
    {
        let operation_id = request.operation_id;
        let operation_is_referenced = self
            .fork_publication_bindings
            .values()
            .map(|row| row.input().operation_id)
            .chain(
                self.fork_publication_artifacts
                    .values()
                    .map(|row| row.input().operation_id),
            )
            .any(|referenced| referenced == operation_id);
        let preflight = AbsentPublicationPreflightV1 {
            operation_is_referenced,
            binding_is_occupied: self.fork_publication_bindings.contains_key(key),
        };
        require_absent_publication_graph(preflight)
            .and_then(|()| authorize_publication(request, Ok(self.key_registry.clone())))
            .and_then(|authorization| {
                self.fork_publication_sources(request)
                    .and_then(|sources| sign_publication(request, &authorization, sources, sign))
            })
            .and_then(|graph| {
                let record_id = graph.receipt.signed_manifest_record_id;
                (!self.fork_publication_record_is_present(record_id))
                    .then_some(graph)
                    .ok_or(ForkManifestPublicationErrorV1::CorruptOrConflicting)
            })
    }
}

impl ForkManifestPublicationPortV1 for MemoryStore {
    fn commit_authorized<E, F>(
        &mut self,
        request: ForkManifestPublicationRequestV1,
        sign: F,
    ) -> Result<ForkPublicationReceiptV1, ForkManifestPublicationErrorV1>
    where
        F: FnOnce(&HeldRegistryAuthorizationV1, &[u8]) -> Result<Signature, E>,
    {
        validate_publication_request(&request)?;
        if let Some(operation) = self.fork_publication_operations.get(&request.operation_id) {
            let input = operation.input();
            let committed = self.read_committed(input.child_timeline_id, input.final_logical_head);
            return recovered_publication_receipt(operation, &request, committed);
        }
        let key = (
            request.child_timeline_id,
            request.expected_final_logical_head,
        );
        let graph = self.sign_new_fork_publication(&request, &key, sign)?;
        self.fork_publication_artifacts
            .insert(graph.receipt.signed_manifest_record_id, graph.artifact);
        self.fork_publication_operations
            .insert(request.operation_id, graph.operation);
        self.fork_publication_bindings.insert(key, graph.binding);
        Ok(graph.receipt)
    }

    fn read_committed(
        &self,
        child_timeline_id: TimelineId,
        final_logical_head: u64,
    ) -> Result<crate::CommittedForkManifestV1, ForkManifestPublicationErrorV1> {
        self.fork_publication_bindings
            .get(&(child_timeline_id, final_logical_head))
            .copied()
            .ok_or(ForkManifestPublicationErrorV1::PublicationMissing)
            .and_then(|binding| {
                let input = binding.input();
                let artifact = self
                    .fork_publication_artifacts
                    .get(&input.signed_manifest_record_id)
                    .cloned();
                self.fork_publication_operations
                    .get(&input.operation_id)
                    .cloned()
                    .zip(artifact)
                    .map(|(operation, artifact)| CommittedPublicationRowsV1 {
                        child_timeline_id,
                        final_logical_head,
                        binding,
                        operation,
                        artifact,
                    })
                    .ok_or(ForkManifestPublicationErrorV1::PublicationConflict)
            })
            .and_then(|rows| {
                let admission = self.fork_publication_admission(child_timeline_id);
                let head = Seq::from_u64(final_logical_head);
                let final_chain_head_hash = self
                    .compute_chain_hash_at_unchecked(child_timeline_id, head)
                    .map_err(PublicationSourceErrorV1::from);
                let suffix = self.fork_publication_suffix(
                    child_timeline_id,
                    publication_parent_head(&admission),
                );
                let sources = CommittedPublicationSourcesV1 {
                    admission,
                    final_chain_head_hash,
                    suffix,
                    registry: Ok(self.key_registry.clone()),
                };
                trusted_committed_manifest(&rows, sources)
            })
    }
}

impl MemoryStore {
    /// Verify FAC1 against the pinned FAH1 policy before the write boundary.
    fn verify_fork_admission_command(
        &self,
        session: &ForkAdmissionAuthoritySessionV1,
        policy: &pos_core::fork_authentication::ForkAuthenticationPolicyV1,
        command: &ForkAdmissionHostCommandV1,
    ) -> Result<VerifiedForkAdmissionCommandV1, pos_core::ForkAdmissionErrorV1> {
        let host = self
            .fork_admission_authority
            .host
            .ok_or(pos_core::ForkAdmissionErrorV1::AuthorityUninitialized)?;
        if !policy
            .digest()
            .is_ok_and(|digest| host.authentication_policy_digest() == digest)
        {
            return Err(pos_core::ForkAdmissionErrorV1::HostAuthorityMismatch);
        }
        verify_command(
            session,
            self.fork_admission_authority.session_identity,
            host,
            policy,
            command,
        )
    }

    /// Apply one verified FAC1 under the exclusive borrow. `containment` is
    /// the ADR-106 r3 erasure decision for a new FCC1.
    fn execute_verified_fork_admission(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        verified: VerifiedForkAdmissionCommandV1,
        containment: Result<(), pos_core::ForkAdmissionErrorV1>,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        let key = (verified.kind(), verified.operation_id());
        if let Some(row) = self.fork_admission_operations.get(&key) {
            return self.exact_fork_admission_result(row, &verified);
        }
        // Keep the authority fence in the same in-memory commit as the
        // operation graph. A rejected FAC1 must not leave a durable fence
        // mutation behind.
        let mut authority = self.fork_admission_authority;
        advance_wall_fence(
            &mut authority,
            self.fork_admission_authority_enabled,
            session,
        )
        .map_err(pos_core::ForkAdmissionErrorV1::from)?;
        let (issued_at, expires_at) = match &verified {
            VerifiedForkAdmissionCommandV1::PrincipalOwner {
                issued_at,
                expires_at,
                ..
            }
            | VerifiedForkAdmissionCommandV1::Fork {
                issued_at,
                expires_at,
                ..
            } => (*issued_at, *expires_at),
        };
        let now = authority.last_authority_wall_time;
        if issued_at > now || expires_at <= now {
            return Err(pos_core::ForkAdmissionErrorV1::Unauthenticated);
        }
        let result = match verified {
            VerifiedForkAdmissionCommandV1::PrincipalOwner {
                operation_id,
                evidence_digest,
                principal_digest,
                owner,
                commitment,
                ..
            } => self.execute_principal_owner_command(
                key,
                &MemoryPrincipalOwnerOperation {
                    operation_id,
                    evidence_digest,
                    principal_digest,
                    owner,
                    commitment,
                },
            ),
            VerifiedForkAdmissionCommandV1::Fork {
                operation_id,
                evidence_digest,
                principal_digest,
                parent_id,
                cut,
                descriptor_hash,
                composition_hash,
                attribution_required,
                child_name,
                commitment,
                ..
            } => self.execute_fork_admission_fork_command(
                key,
                MemoryForkAdmissionOperation {
                    operation_id,
                    evidence_digest,
                    principal_digest,
                    parent_id,
                    cut,
                    descriptor_hash,
                    composition_hash,
                    attribution_required,
                    child_name,
                    commitment,
                },
                containment,
            ),
        };
        if result.is_ok() {
            self.fork_admission_authority = authority;
        }
        result
    }

    fn execute_principal_owner_command(
        &mut self,
        key: (ForkAdmissionOperationKindV1, Hash),
        command: &MemoryPrincipalOwnerOperation,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        let MemoryPrincipalOwnerOperation {
            operation_id,
            evidence_digest,
            principal_digest,
            owner,
            commitment,
        } = *command;
        // ADR-099: one Principal maps to exactly one immutable Owner. An equal
        // Owner under a new operation ID resolves to the committed binding
        // without writing; only an unequal Owner is a rebinding conflict.
        if let Some(existing) = self.fork_principal_owner_bindings.get(&principal_digest) {
            return (existing.input().owner == owner)
                .then(|| ForkAdmissionOperationResultV1::PrincipalOwner(existing.clone()))
                .ok_or(pos_core::ForkAdmissionErrorV1::PrincipalOwnerConflict);
        }
        // Verified POC1 facts carry nonzero operation and Principal digests,
        // so construction cannot fail; any failure still fails closed.
        PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id,
            principal_digest,
            owner,
            origin: ForkAuthorityOriginV1::Local,
        })
        .ok()
        .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        .map(|binding| {
            let result_digest = binding.digest();
            self.fork_principal_owner_bindings
                .insert(principal_digest, binding.clone());
            self.fork_principal_owner_binding_digests
                .insert(result_digest, principal_digest);
            self.fork_admission_operations.insert(
                key,
                ForkAdmissionOperationRowV1 {
                    kind: ForkAdmissionOperationKindV1::PrincipalOwner,
                    operation_id,
                    evidence_digest,
                    commitment,
                    result_digest,
                    child_id: None,
                },
            );
            ForkAdmissionOperationResultV1::PrincipalOwner(binding)
        })
    }

    fn execute_fork_admission_fork_command(
        &mut self,
        key: (ForkAdmissionOperationKindV1, Hash),
        command: MemoryForkAdmissionOperation,
        containment: Result<(), pos_core::ForkAdmissionErrorV1>,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        let MemoryForkAdmissionOperation {
            operation_id,
            evidence_digest,
            principal_digest,
            parent_id,
            cut,
            descriptor_hash,
            composition_hash,
            attribution_required,
            child_name,
            commitment,
        } = command;
        let binding = self.admitted_fork_binding(principal_digest, parent_id, containment)?;
        let head = self
            .logical_head_unchecked(parent_id)
            .map_err(|_| pos_core::ForkAdmissionErrorV1::ParentChanged)?;
        if head.as_u64() != cut {
            return Err(pos_core::ForkAdmissionErrorV1::StaleFoldBoundary);
        }
        let meta = TimelineMeta::forked_from(parent_id, Seq::from_u64(cut), child_name);
        let child = Timeline::new(meta);
        let chain_head = self
            .compute_chain_hash_at_unchecked(parent_id, Seq::from_u64(cut))
            .map_err(|_| pos_core::ForkAdmissionErrorV1::ParentChanged)?;
        // Verified FCC1 facts and the fresh child ID satisfy every FAR1
        // invariant; any construction failure still fails closed.
        ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
            operation_id,
            principal_owner_binding_digest: binding.digest(),
            creator: binding.input().owner,
            parent_timeline_id: parent_id,
            child_timeline_id: child.id(),
            room_revision_descriptor_hash: descriptor_hash,
            parent_logical_head: cut,
            parent_chain_head_hash: chain_head,
            completed_fold_cursor: cut,
            post_fold_tick_boundary: cut,
            plugin_composition_hash: composition_hash,
            attribution_required,
            origin: ForkAttributionOriginV1::Local,
        })
        .ok()
        .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        .map(|admission| {
            let receipt = ForkAdmissionReceiptV1 {
                child_id: child.id(),
                admission_digest: admission.digest(),
            };
            self.timelines
                .insert(child.id(), TimelineState::new(child, chain_head));
            self.fork_admissions.insert(receipt.child_id, admission);
            self.fork_admission_operations.insert(
                key,
                ForkAdmissionOperationRowV1 {
                    kind: ForkAdmissionOperationKindV1::Fork,
                    operation_id,
                    evidence_digest,
                    commitment,
                    result_digest: receipt.admission_digest,
                    child_id: Some(receipt.child_id),
                },
            );
            ForkAdmissionOperationResultV1::Fork(receipt)
        })
    }

    /// ADR-106 r3 steps 5 to 7 in order: the committed POB1 (`InvalidRequest`
    /// when absent), parent visibility, then erasure containment.
    fn admitted_fork_binding(
        &self,
        principal_digest: Hash,
        parent: TimelineId,
        containment: Result<(), pos_core::ForkAdmissionErrorV1>,
    ) -> Result<PrincipalOwnerBindingV1, pos_core::ForkAdmissionErrorV1> {
        let binding = self
            .fork_principal_owner_bindings
            .get(&principal_digest)
            .cloned()
            .ok_or(pos_core::ForkAdmissionErrorV1::InvalidRequest)?;
        self.admitted_fork_parent_gate(parent, containment)?;
        Ok(binding)
    }

    /// ADR-106 r3 steps 6 and 7: an absent or geographic parent is
    /// indistinguishable from a changed one, and visibility precedes the
    /// erasure containment decision.
    ///
    /// Unlike `SQLite`, the in-memory Timeline and geographic-marker reads
    /// cannot fail, so the `StorageIndeterminate` marker outcome has no
    /// in-memory cause.
    fn admitted_fork_parent_gate(
        &self,
        parent: TimelineId,
        containment: Result<(), pos_core::ForkAdmissionErrorV1>,
    ) -> Result<(), pos_core::ForkAdmissionErrorV1> {
        let visible =
            self.timelines.contains_key(&parent) && !self.geographic_timelines.contains(&parent);
        if visible {
            containment
        } else {
            Err(pos_core::ForkAdmissionErrorV1::ParentChanged)
        }
    }

    fn exact_fork_admission_result(
        &self,
        row: &ForkAdmissionOperationRowV1,
        command: &VerifiedForkAdmissionCommandV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        // ADR-106: committed corruption precedes Conflict, so the complete
        // durable graph is validated before the presented intent is compared.
        self.stored_fork_admission_result(row).and_then(|result| {
            if row.commitment == command.commitment()
                && row.evidence_digest == command.evidence_digest()
            {
                Ok(result)
            } else {
                Err(pos_core::ForkAdmissionErrorV1::Conflict)
            }
        })
    }

    fn stored_fork_admission_result(
        &self,
        row: &ForkAdmissionOperationRowV1,
    ) -> Result<ForkAdmissionOperationResultV1, pos_core::ForkAdmissionErrorV1> {
        let store_id = self
            .fork_admission_authority
            .host
            .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)?
            .store_id();
        match (row.kind, row.child_id) {
            (ForkAdmissionOperationKindV1::PrincipalOwner, None) => self
                .stored_principal_owner_binding(store_id, row)
                .map(ForkAdmissionOperationResultV1::PrincipalOwner),
            (ForkAdmissionOperationKindV1::Fork, Some(child_id)) => {
                let admission = self
                    .fork_admissions
                    .get(&child_id)
                    .filter(|admission| {
                        admission.digest() == row.result_digest
                            && admission.input().operation_id == row.operation_id
                            && admission.input().child_timeline_id == child_id
                    })
                    .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)?;
                // The POB1 behind FAR1 must itself be a committed, exact
                // operation root; an orphaned binding is corrupt authority.
                let binding = self
                    .principal_owner_binding_by_digest(
                        admission.input().principal_owner_binding_digest,
                    )
                    .and_then(|binding| {
                        self.fork_admission_operations.get(&(
                            ForkAdmissionOperationKindV1::PrincipalOwner,
                            binding.input().operation_id,
                        ))
                    })
                    .filter(|binding_row| binding_row.child_id.is_none())
                    .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
                    .and_then(|binding_row| {
                        self.stored_principal_owner_binding(store_id, binding_row)
                    })?;
                if binding.digest() != admission.input().principal_owner_binding_digest
                    || binding.input().owner != admission.input().creator
                {
                    return Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority);
                }
                let parent_chain_head = self
                    .compute_chain_hash_at_unchecked(
                        admission.input().parent_timeline_id,
                        Seq::from_u64(admission.input().parent_logical_head),
                    )
                    .map_err(|_| pos_core::ForkAdmissionErrorV1::CorruptAuthority)?;
                if parent_chain_head != admission.input().parent_chain_head_hash {
                    return Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority);
                }
                let child = self
                    .timelines
                    .get(&child_id)
                    .filter(|child| {
                        child.timeline.meta.fork_point
                            == Some((
                                admission.input().parent_timeline_id,
                                Seq::from_u64(admission.input().parent_logical_head),
                            ))
                    })
                    .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)?;
                let child_name = child
                    .timeline
                    .meta
                    .name
                    .as_deref()
                    .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)?;
                if fork_commitment(
                    store_id,
                    binding.input().principal_digest,
                    row.evidence_digest,
                    admission,
                    child_name,
                ) != row.commitment
                {
                    return Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority);
                }
                Ok(ForkAdmissionOperationResultV1::Fork(
                    ForkAdmissionReceiptV1 {
                        child_id,
                        admission_digest: row.result_digest,
                    },
                ))
            }
            _ => Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority),
        }
    }

    /// Keyed POB1 lookup by binding digest through the digest index.
    fn principal_owner_binding_by_digest(&self, digest: Hash) -> Option<&PrincipalOwnerBindingV1> {
        self.fork_principal_owner_binding_digests
            .get(&digest)
            .and_then(|principal_digest| self.fork_principal_owner_bindings.get(principal_digest))
            .filter(|binding| binding.digest() == digest)
    }

    /// Validate one POB1 operation row against its keyed binding and
    /// reconstructed commitment.
    fn stored_principal_owner_binding(
        &self,
        store_id: Hash,
        row: &ForkAdmissionOperationRowV1,
    ) -> Result<PrincipalOwnerBindingV1, pos_core::ForkAdmissionErrorV1> {
        self.principal_owner_binding_by_digest(row.result_digest)
            .filter(|binding| {
                binding.input().operation_id == row.operation_id
                    && principal_owner_commitment(store_id, binding, row.evidence_digest)
                        == row.commitment
            })
            .cloned()
            .ok_or(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
    }
}

#[derive(Clone, Copy)]
struct MemoryPrincipalOwnerOperation {
    operation_id: Hash,
    evidence_digest: Hash,
    principal_digest: Hash,
    owner: pos_core::OwnerIdV1,
    commitment: Hash,
}

struct MemoryForkAdmissionOperation {
    operation_id: Hash,
    evidence_digest: Hash,
    principal_digest: Hash,
    parent_id: TimelineId,
    cut: u64,
    descriptor_hash: Hash,
    composition_hash: Hash,
    attribution_required: bool,
    child_name: String,
    commitment: Hash,
}

impl AuthorityPersistencePortV1 for MemoryStore {
    fn bind_authority_persistence(
        &mut self,
        binding: AuthorityPersistenceBindingV1,
    ) -> Result<(), AuthorityPersistenceErrorV1> {
        match self.authority_persistence_binding {
            Some(bound) if bound != binding => Err(AuthorityPersistenceErrorV1::Unavailable),
            _ => {
                self.authority_persistence_binding = Some(binding);
                Ok(())
            }
        }
    }

    fn issue_capability_grant(
        &mut self,
        permit: AuthorityMutationPermitV1,
        grant: &CapabilityGrantV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        if self.authority_persistence_binding != Some(permit.persistence_binding()) {
            return Err(AuthorityPersistenceErrorV1::Unavailable);
        }
        let mut pending = self.authority_state.clone();
        match pending.issue_grant(permit, grant.clone()) {
            Ok(outcome) => {
                self.authority_state = pending;
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
    }

    fn revoke_capability_grant(
        &mut self,
        permit: AuthorityMutationPermitV1,
        revocation: &CapabilityRevocationV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        if self.authority_persistence_binding != Some(permit.persistence_binding()) {
            return Err(AuthorityPersistenceErrorV1::Unavailable);
        }
        let mut pending = self.authority_state.clone();
        match pending.revoke_grant(permit, revocation.clone()) {
            Ok(outcome) => {
                self.authority_state = pending;
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
    }

    fn load_authority(
        &self,
        leaf_grant_id: Hash,
    ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
        self.authority_state.resolve(leaf_grant_id)
    }
}

#[derive(Clone, Copy)]
struct GeographicAdmissionDedupRecord {
    timeline: TimelineId,
    intent: GeoLocationAdmissionIntentV1,
    event_id: EventId,
    expires_at: WallTime,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::with_default_components(Box::new(pos_crypto::chain::Blake3Hasher))
    }
}

impl ErasureStateResolverV1 for MemoryStore {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<pos_core::ErasureStateV1>, ErasureErrorV1> {
        self.erasure_states
            .get(&digest)
            .map(|bytes| {
                pos_core::ErasureStateV1::from_canonical_cbor(bytes).and_then(|state| {
                    if state.state_digest() == digest {
                        Ok(state)
                    } else {
                        Err(ErasureErrorV1::ProvenanceMissing)
                    }
                })
            })
            .transpose()
    }
}

impl crate::ErasureRejoinPersistencePortV1 for MemoryStore {
    fn store_rejoin_proof(
        &mut self,
        proof: &pos_core::ErasureRejoinProofV1,
    ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
        let bytes = crate::canonical_rejoin_bytes(proof);
        match self.erasure_evidence.entry(proof.reference()) {
            Entry::Vacant(entry) => {
                entry.insert(bytes);
                Ok(ErasureCasOutcomeV1::Applied)
            }
            Entry::Occupied(entry) if entry.get().as_slice() == bytes.as_slice() => {
                Ok(ErasureCasOutcomeV1::ExactRetry)
            }
            Entry::Occupied(_) => Err(ErasureErrorV1::ProvenanceMissing),
        }
    }

    fn load_rejoin_proof(
        &self,
        reference: ErasureReferenceV1,
    ) -> Result<Option<pos_core::ErasureRejoinProofV1>, ErasureErrorV1> {
        self.erasure_evidence
            .get(&reference)
            .map(|bytes| pos_core::ErasureRejoinProofV1::from_canonical_cbor(bytes))
            .map(|result| {
                result.and_then(|proof| crate::validate_rejoin_proof_reference(reference, proof))
            })
            .transpose()
    }
}

impl ErasureInventoryPersistencePortV1 for MemoryStore {
    fn complete_erasure_inventory_snapshot(
        &mut self,
        maximum_requests: usize,
    ) -> Result<ErasurePersistenceInventorySnapshotV1, ErasureErrorV1> {
        self.complete_erasure_inventory_snapshot_with_limits(
            ErasureRecoveryLimitsV1::from_maximum_requests(maximum_requests)?,
        )
    }

    fn complete_erasure_inventory_snapshot_with_limits(
        &mut self,
        limits: ErasureRecoveryLimitsV1,
    ) -> Result<ErasurePersistenceInventorySnapshotV1, ErasureErrorV1> {
        let snapshot = self
            .ensure_inventory_snapshot_limits(limits)
            .and_then(|()| {
                let mut request_heads = Vec::new();
                request_heads
                    .try_reserve(self.erasure_records.len())
                    .map_err(|_| ErasureErrorV1::ScopeInvalid)
                    .and_then(|()| {
                        request_heads.extend(
                            self.erasure_records
                                .iter()
                                .map(|(request, (manifest, _))| (*request, *manifest)),
                        );
                        let mut topology = Vec::new();
                        topology
                            .try_reserve(self.timelines.len())
                            .map_err(|_| ErasureErrorV1::ScopeInvalid)
                            .and_then(|()| {
                                topology.extend(self.timelines.keys().copied());
                                topology.sort_unstable();
                                ErasurePersistenceInventorySnapshotV1::new_with_limits(
                                    request_heads,
                                    topology,
                                    limits,
                                )
                            })
                    })
            })?;
        self.erasure_inventory_generation = Some(snapshot.generation());
        Ok(snapshot)
    }
}

impl ErasureForkPersistencePortV1 for MemoryStore {
    fn commit_fork_admission(
        &mut self,
        permit: &ErasureTopologyTransitionPermitV1,
        admission: PreparedErasureForkBatchV1,
    ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
        self.commit_fork_admission_impl(permit, &admission)
    }

    fn recover_fork_admission(
        &mut self,
        operation: ErasureReferenceV1,
        successor_inventory: &ErasureVerifiedInventoryV1,
    ) -> Result<Option<ErasureForkRecoveryV1>, ErasureErrorV1> {
        self.recover_fork_admission_impl(operation, successor_inventory)
    }
}

impl MemoryStore {
    fn commit_fork_admission_impl(
        &mut self,
        permit: &ErasureTopologyTransitionPermitV1,
        admission: &PreparedErasureForkBatchV1,
    ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
        self.ensure_host_transition_permit(permit)
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
        let binding = admission.binding_digest();
        let operation = admission.operation();
        let proof = admission.recovery_proof()?;
        let child = admission.child().clone();
        let (parent, at_seq) = child.fork_point.ok_or(ErasureErrorV1::PolicyConflict)?;

        if let Some(stored_result) = self.erasure_fork_admissions.get(&operation) {
            let chain_head = self
                .compute_chain_hash_at_unchecked(parent, at_seq)
                .map_err(|_| ErasureErrorV1::PolicyConflict)?;
            let exact_child = self.memory_fork_child_is_exact(&child, chain_head)?;
            let exact_manifest = self.persisted_fork_erasure_mutations_are_exact(admission);
            let exact_proof = self.erasure_fork_recovery_proofs.get(&operation) == Some(&proof);
            return ((
                stored_result.binding_digest(),
                exact_child,
                exact_manifest,
                exact_proof,
            ) == (binding, true, true, true))
                .then_some(ErasureCasOutcomeV1::ExactRetry)
                .ok_or(ErasureErrorV1::PolicyConflict);
        }

        let generation = self
            .complete_erasure_inventory_snapshot(ERASURE_MAX_INVENTORY_REQUESTS)?
            .generation();
        if generation != admission.expected_inventory_generation() {
            return Err(ErasureErrorV1::StaleGeneration);
        }
        let chain_head = self
            .compute_chain_hash_at_unchecked(parent, at_seq)
            .map_err(|_| ErasureErrorV1::PolicyConflict)?;
        let timeline = Timeline::new(child);
        let mut delta = MemoryErasureCasDelta::default();
        for prepared in admission.admissions() {
            let mutation = prepared.mutation();
            // The complete inventory-generation comparison above binds every
            // active request head, and core requires exactly one admission for
            // each affected request before constructing the batch.
            stage_memory_erasure_mutation(self, mutation, &mut delta)?;
        }
        apply_memory_erasure_delta(self, delta);
        for prepared in admission.admissions() {
            let mutation = prepared.mutation();
            self.erasure_records.insert(
                mutation.request(),
                (
                    mutation.next_manifest().digest(),
                    mutation.next_manifest().canonical_cbor().to_vec(),
                ),
            );
        }
        self.timelines
            .insert(timeline.id(), TimelineState::new(timeline, chain_head));
        let result = admission.recovery_result()?;
        self.erasure_fork_recovery_proofs.insert(operation, proof);
        self.erasure_fork_admissions.insert(operation, result);
        self.erasure_inventory_generation = Some(admission.successor_inventory().generation());
        Ok(ErasureCasOutcomeV1::Applied)
    }

    fn recover_fork_admission_impl(
        &self,
        operation: ErasureReferenceV1,
        successor_inventory: &ErasureVerifiedInventoryV1,
    ) -> Result<Option<ErasureForkRecoveryV1>, ErasureErrorV1> {
        let Some(result) = self.erasure_fork_admissions.get(&operation).cloned() else {
            if self.erasure_fork_recovery_proofs.contains_key(&operation) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            return Ok(None);
        };
        let proof = self
            .erasure_fork_recovery_proofs
            .get(&operation)
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        proof.validate_complete_for_inventory_with_persisted_state(
            &result,
            successor_inventory,
            || {
                self.memory_fork_recovery_proof_is_exact(proof)?;
                self.verify_memory_fork_child(&result)
            },
        )?;
        Ok(Some(result))
    }
}

impl MemoryStore {
    fn verify_memory_fork_child(
        &self,
        result: &ErasureForkRecoveryV1,
    ) -> Result<(), ErasureErrorV1> {
        let (parent, at_seq) = result.fork_point();
        let chain_head = self
            .compute_chain_hash_at_unchecked(parent, at_seq)
            .map_err(|_| ErasureErrorV1::ProvenanceMissing)?;
        self.memory_fork_child_is_exact(result.child(), chain_head)?
            .then_some(())
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    }

    fn memory_fork_child_is_exact(
        &self,
        child: &TimelineMeta,
        chain_head: Hash,
    ) -> Result<bool, ErasureErrorV1> {
        let Some(state) = self.timelines.get(&child.id) else {
            return Ok(false);
        };
        crate::fork_child_is_exact(crate::ForkChildVerificationInput {
            expected_meta: child,
            actual_meta: &state.timeline.meta,
            stored_head: state.timeline.head,
            stored_chain_head: state.chain_head.as_bytes(),
            chain_head,
            events: state
                .events
                .iter()
                .map(|event| Ok((event.seq, event.id, event.payload.clone()))),
            hasher: self.hasher.as_ref(),
        })
    }

    fn persisted_fork_erasure_mutations_are_exact(
        &self,
        admission: &PreparedErasureForkBatchV1,
    ) -> bool {
        admission.admissions().iter().all(|prepared| {
            let mutation = prepared.mutation();
            // The current manifest is a mutable head and may have advanced
            // since this operation's receipt. Its immutable evidence and
            // indexed extension remain the authority for exact replay.
            memory_mutation_is_exact(self, mutation)
        })
    }

    fn memory_fork_recovery_proof_is_exact(
        &self,
        proof: &ErasureForkRecoveryProofV1,
    ) -> Result<(), ErasureErrorV1> {
        for mutation in proof.admissions() {
            // `erasure_records` is the mutable current head and may have
            // advanced through a later Fork. The immutable effect below
            // proves this admission was committed; the verified inventory
            // separately proves its extension remains in the current chain.
            if !mutation
                .objects()
                .iter()
                .any(|object| object.reference() == mutation.extension())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            for object in mutation.objects() {
                let Some(bytes) = self.erasure_evidence.get(&object.reference()) else {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                };
                if ErasureForkRecoveryProofV1::bytes_digest(bytes) != object.bytes_digest() {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            for state in mutation.states() {
                let Some(bytes) = self.erasure_states.get(&state.reference()) else {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                };
                if ErasureForkRecoveryProofV1::bytes_digest(bytes) != state.bytes_digest() {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            for index in mutation.index_inserts() {
                let (stored, reference) = match *index {
                    ErasureIndexInsertV1::AttemptPage { ordinal, reference } => (
                        self.erasure_attempt_pages
                            .get(&(mutation.request(), ordinal)),
                        reference,
                    ),
                    ErasureIndexInsertV1::ScopeNode { ordinal, reference } => (
                        self.erasure_scope_nodes.get(&(mutation.request(), ordinal)),
                        reference,
                    ),
                    ErasureIndexInsertV1::AdministrativeResolution { ordinal, reference } => (
                        self.erasure_administrative_resolutions
                            .get(&(mutation.request(), ordinal)),
                        reference,
                    ),
                };
                if stored != Some(&reference) {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            let Some((effect_digest, bytes)) = self.erasure_effects.get(&mutation.next_manifest())
            else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let effect = pos_core::ErasureCasEffectV1::from_canonical_cbor(bytes)?;
            if effect.identity() != *effect_digest
                || effect.subject() != mutation.effect_subject()
                || ErasureForkRecoveryProofV1::bytes_digest(bytes) != mutation.effect_bytes_digest()
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if mutation.effect_subject().is_some_and(|subject| {
                self.erasure_effect_subjects.get(&subject) != Some(&mutation.next_manifest())
            }) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }
}

impl ErasurePersistencePortV1 for MemoryStore {
    fn read_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<StoredErasureManifestV1>, ErasureErrorV1> {
        Ok(self
            .erasure_records
            .get(&request)
            .map(|(digest, bytes)| StoredErasureManifestV1::from_stored(*digest, bytes.clone())))
    }
    fn read_object(&self, reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1> {
        self.erasure_evidence
            .get(&reference)
            .cloned()
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    }
    fn read_effect(
        &self,
        manifest: ErasureReferenceV1,
    ) -> Result<pos_core::ErasureCasEffectV1, ErasureErrorV1> {
        self.erasure_effects
            .get(&manifest)
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(decode_memory_effect)
    }
    fn effect_manifest(
        &self,
        subject: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        Ok(self.erasure_effect_subjects.get(&subject).copied())
    }
    fn attempt_page_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        Ok(self.erasure_attempt_pages.get(&(request, ordinal)).copied())
    }
    fn attempt_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        memory_index_count(&self.erasure_attempt_pages, request)
    }
    fn scope_node_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        Ok(self.erasure_scope_nodes.get(&(request, ordinal)).copied())
    }
    fn scope_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1> {
        memory_index_count(&self.erasure_scope_nodes, request)
    }
    fn administrative_resolution_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        Ok(self
            .erasure_administrative_resolutions
            .get(&(request, ordinal))
            .copied())
    }
    fn administrative_resolution_index_count(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<u64, ErasureErrorV1> {
        memory_index_count(&self.erasure_administrative_resolutions, request)
    }
    fn recovery_error_refs(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
        let references = self
            .erasure_recovery_errors
            .get(&request)
            .into_iter()
            .flat_map(|references| references.iter().copied())
            .take(ERASURE_MAX_RECOVERY_ERRORS + 1)
            .collect::<Vec<_>>();
        if references.len() > ERASURE_MAX_RECOVERY_ERRORS {
            Err(ErasureErrorV1::ScopeInvalid)
        } else {
            Ok(references)
        }
    }
    fn append_recovery_error(
        &mut self,
        object: PreparedErasureRecoveryErrorV1,
    ) -> Result<(), ErasureErrorV1> {
        let request = object.request();
        let reference = object.reference();
        let bytes = object.canonical_cbor();
        if self
            .erasure_recovery_errors
            .get(&request)
            .is_some_and(|references| {
                !references.contains(&reference) && references.len() >= ERASURE_MAX_RECOVERY_ERRORS
            })
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if self
            .erasure_evidence
            .get(&reference)
            .is_some_and(|existing| existing.as_slice() != bytes)
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.erasure_evidence
            .entry(reference)
            .or_insert_with(|| bytes.to_vec());
        self.erasure_recovery_errors
            .entry(request)
            .or_default()
            .insert(reference);
        Ok(())
    }
    fn compare_and_swap(
        &mut self,
        mutation: PreparedErasureCasV1,
    ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
        let request = mutation.request();
        let result = self
            .erasure_records
            .get(&request)
            .map(|(digest, bytes)| {
                StoredErasureManifestV1::new(*digest, bytes.clone()).map(|stored| stored.digest())
            })
            .transpose()
            .and_then(|current_digest| apply_memory_erasure_cas(self, &mutation, current_digest));
        self.invalidate_inventory_generation_after_cas(result);
        result
    }
}

fn apply_memory_erasure_cas(
    store: &mut MemoryStore,
    mutation: &PreparedErasureCasV1,
    current_digest: Option<ErasureReferenceV1>,
) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
    let request = mutation.request();
    let next = mutation.next_manifest();
    if store
        .erasure_records
        .get(&request)
        .is_some_and(|(digest, bytes)| {
            *digest == next.digest() && bytes.as_slice() == next.canonical_cbor()
        })
    {
        return memory_mutation_is_exact(store, mutation)
            .then_some(ErasureCasOutcomeV1::ExactRetry)
            .ok_or(ErasureErrorV1::PolicyConflict);
    }
    if current_digest != mutation.expected_manifest_digest() {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    stage_memory_erasure_delta(store, mutation).map(|delta| {
        apply_memory_erasure_delta(store, delta);
        store
            .erasure_records
            .insert(request, (next.digest(), next.canonical_cbor().to_vec()));
        ErasureCasOutcomeV1::Applied
    })
}

// Own only the bounded mutation delta. All fallible validation completes
// before these entries are applied to the store, preserving CAS atomicity
// without cloning unrelated requests' retained state.
#[derive(Default)]
struct MemoryErasureCasDelta {
    evidence: BTreeMap<ErasureReferenceV1, Vec<u8>>,
    states: BTreeMap<ErasureReferenceV1, Vec<u8>>,
    attempts: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    scopes: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    resolutions: BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    effects: BTreeMap<ErasureReferenceV1, (ErasureReferenceV1, Vec<u8>)>,
    effect_subjects: BTreeMap<ErasureReferenceV1, ErasureReferenceV1>,
}

fn stage_memory_erasure_delta(
    store: &MemoryStore,
    mutation: &PreparedErasureCasV1,
) -> Result<MemoryErasureCasDelta, ErasureErrorV1> {
    let mut delta = MemoryErasureCasDelta::default();
    stage_memory_erasure_mutation(store, mutation, &mut delta).map(|()| delta)
}

fn stage_memory_erasure_mutation(
    store: &MemoryStore,
    mutation: &PreparedErasureCasV1,
    delta: &mut MemoryErasureCasDelta,
) -> Result<(), ErasureErrorV1> {
    stage_memory_objects(store, mutation.new_objects(), delta)
        .and_then(|()| stage_memory_states(store, mutation.new_states(), delta))
        .and_then(|()| stage_memory_indexes(store, mutation, delta))
        .and_then(|()| stage_memory_effect(store, mutation, delta))
}

fn stage_memory_objects(
    store: &MemoryStore,
    objects: &[ErasurePersistenceObjectV1],
    delta: &mut MemoryErasureCasDelta,
) -> Result<(), ErasureErrorV1> {
    objects.iter().try_for_each(|object| {
        stage_exact(
            &store.erasure_evidence,
            &mut delta.evidence,
            object.reference(),
            object.canonical_cbor(),
        )
    })
}

fn stage_memory_states(
    store: &MemoryStore,
    states: &[ErasurePersistedStateV1],
    delta: &mut MemoryErasureCasDelta,
) -> Result<(), ErasureErrorV1> {
    states.iter().try_for_each(|state| {
        validate_memory_state_predecessor(store, &delta.states, state).and_then(|()| {
            stage_exact(
                &store.erasure_states,
                &mut delta.states,
                state.reference(),
                state.canonical_cbor(),
            )
        })
    })
}

fn validate_memory_state_predecessor(
    store: &MemoryStore,
    staged: &BTreeMap<ErasureReferenceV1, Vec<u8>>,
    state: &ErasurePersistedStateV1,
) -> Result<(), ErasureErrorV1> {
    state.state().previous_state().map_or(Ok(()), |previous| {
        staged
            .get(&previous)
            .or_else(|| store.erasure_states.get(&previous))
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|bytes| pos_core::ErasureStateV1::from_canonical_cbor(bytes))
            .and_then(|previous_state| state.state().validate_predecessor(&previous_state))
    })
}

fn stage_memory_indexes(
    store: &MemoryStore,
    mutation: &PreparedErasureCasV1,
    delta: &mut MemoryErasureCasDelta,
) -> Result<(), ErasureErrorV1> {
    mutation.index_inserts().iter().try_for_each(|index| {
        let (existing, staged, ordinal, reference) = match *index {
            ErasureIndexInsertV1::AttemptPage { ordinal, reference } => (
                &store.erasure_attempt_pages,
                &mut delta.attempts,
                ordinal,
                reference,
            ),
            ErasureIndexInsertV1::ScopeNode { ordinal, reference } => (
                &store.erasure_scope_nodes,
                &mut delta.scopes,
                ordinal,
                reference,
            ),
            ErasureIndexInsertV1::AdministrativeResolution { ordinal, reference } => (
                &store.erasure_administrative_resolutions,
                &mut delta.resolutions,
                ordinal,
                reference,
            ),
        };
        stage_index(existing, staged, mutation.request(), ordinal, reference)
    })
}

fn stage_memory_effect(
    store: &MemoryStore,
    mutation: &PreparedErasureCasV1,
    delta: &mut MemoryErasureCasDelta,
) -> Result<(), ErasureErrorV1> {
    let manifest = mutation.next_manifest().digest();
    mutation
        .effect()
        .to_canonical_cbor()
        .and_then(|effect_bytes| {
            stage_effect(
                &store.erasure_effects,
                &mut delta.effects,
                manifest,
                mutation.effect(),
                &effect_bytes,
            )
        })
        .and_then(|()| {
            stage_effect_subject(
                &store.erasure_effect_subjects,
                &mut delta.effect_subjects,
                mutation.effect().subject(),
                manifest,
            )
        })
}

fn stage_effect_subject(
    existing: &BTreeMap<ErasureReferenceV1, ErasureReferenceV1>,
    staged: &mut BTreeMap<ErasureReferenceV1, ErasureReferenceV1>,
    subject: Option<ErasureReferenceV1>,
    manifest: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    subject.map_or(Ok(()), |subject| match existing.get(&subject) {
        Some(current) if *current != manifest => Err(ErasureErrorV1::PolicyConflict),
        Some(_) => Ok(()),
        None => {
            staged.insert(subject, manifest);
            Ok(())
        }
    })
}

fn apply_memory_erasure_delta(store: &mut MemoryStore, delta: MemoryErasureCasDelta) {
    for (reference, bytes) in delta.evidence {
        store.erasure_evidence.entry(reference).or_insert(bytes);
    }
    for (reference, bytes) in delta.states {
        store.erasure_states.entry(reference).or_insert(bytes);
    }
    for (key, reference) in delta.attempts {
        store.erasure_attempt_pages.entry(key).or_insert(reference);
    }
    for (key, reference) in delta.scopes {
        store.erasure_scope_nodes.entry(key).or_insert(reference);
    }
    for (key, reference) in delta.resolutions {
        store
            .erasure_administrative_resolutions
            .entry(key)
            .or_insert(reference);
    }
    for (manifest, effect) in delta.effects {
        store.erasure_effects.entry(manifest).or_insert(effect);
    }
    for (subject, manifest) in delta.effect_subjects {
        store
            .erasure_effect_subjects
            .entry(subject)
            .or_insert(manifest);
    }
}

fn stage_exact(
    existing: &BTreeMap<ErasureReferenceV1, Vec<u8>>,
    staged: &mut BTreeMap<ErasureReferenceV1, Vec<u8>>,
    reference: ErasureReferenceV1,
    bytes: &[u8],
) -> Result<(), ErasureErrorV1> {
    if let Some(value) = existing.get(&reference) {
        return (value.as_slice() == bytes)
            .then_some(())
            .ok_or(ErasureErrorV1::ProvenanceMissing);
    }
    insert_or_verify_staged(
        staged,
        reference,
        bytes.to_vec(),
        ErasureErrorV1::ProvenanceMissing,
    )
}

fn stage_effect(
    existing: &BTreeMap<ErasureReferenceV1, (ErasureReferenceV1, Vec<u8>)>,
    staged: &mut BTreeMap<ErasureReferenceV1, (ErasureReferenceV1, Vec<u8>)>,
    manifest: ErasureReferenceV1,
    effect: &pos_core::ErasureCasEffectV1,
    bytes: &[u8],
) -> Result<(), ErasureErrorV1> {
    if let Some(value) = existing.get(&manifest) {
        return decode_memory_effect(value).and_then(|stored| {
            (stored == *effect && value.1.as_slice() == bytes)
                .then_some(())
                .ok_or(ErasureErrorV1::ProvenanceMissing)
        });
    }
    insert_effect_exact(staged, manifest, effect, bytes)
}

fn stage_index(
    existing: &BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    staged: &mut BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    request: ErasureReferenceV1,
    ordinal: u64,
    reference: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    if let Some(value) = existing.get(&(request, ordinal)) {
        return (*value == reference)
            .then_some(())
            .ok_or(ErasureErrorV1::PolicyConflict);
    }
    insert_index(staged, request, ordinal, reference)
}

fn insert_or_verify_staged<K: Ord, V: Eq>(
    staged: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    conflict: ErasureErrorV1,
) -> Result<(), ErasureErrorV1> {
    match staged.entry(key) {
        Entry::Occupied(entry) => (entry.get() == &value).then_some(()).ok_or(conflict),
        Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
    }
}

fn memory_mutation_is_exact(store: &MemoryStore, mutation: &PreparedErasureCasV1) -> bool {
    mutation.new_objects().iter().all(|object| {
        store
            .erasure_evidence
            .get(&object.reference())
            .map(Vec::as_slice)
            == Some(object.canonical_cbor())
    }) && mutation.new_states().iter().all(|state| {
        store
            .erasure_states
            .get(&state.reference())
            .map(Vec::as_slice)
            == Some(state.canonical_cbor())
    }) && mutation.index_inserts().iter().all(|index| {
        let (map, ordinal, reference) = match *index {
            ErasureIndexInsertV1::AttemptPage { ordinal, reference } => {
                (&store.erasure_attempt_pages, ordinal, reference)
            }
            ErasureIndexInsertV1::ScopeNode { ordinal, reference } => {
                (&store.erasure_scope_nodes, ordinal, reference)
            }
            ErasureIndexInsertV1::AdministrativeResolution { ordinal, reference } => (
                &store.erasure_administrative_resolutions,
                ordinal,
                reference,
            ),
        };
        map.get(&(mutation.request(), ordinal)) == Some(&reference)
    }) && store
        .erasure_effects
        .get(&mutation.next_manifest().digest())
        .and_then(|stored| decode_memory_effect(stored).ok())
        .as_ref()
        == Some(mutation.effect())
        && mutation.effect().subject().is_none_or(|subject| {
            store.erasure_effect_subjects.get(&subject) == Some(&mutation.next_manifest().digest())
        })
}

fn decode_memory_effect(
    (digest, bytes): &(ErasureReferenceV1, Vec<u8>),
) -> Result<pos_core::ErasureCasEffectV1, ErasureErrorV1> {
    pos_core::ErasureCasEffectV1::from_canonical_cbor(bytes).and_then(|effect| {
        (effect.identity() == *digest)
            .then_some(effect)
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    })
}

fn insert_effect_exact(
    map: &mut BTreeMap<ErasureReferenceV1, (ErasureReferenceV1, Vec<u8>)>,
    manifest: ErasureReferenceV1,
    effect: &pos_core::ErasureCasEffectV1,
    bytes: &[u8],
) -> Result<(), ErasureErrorV1> {
    match map.entry(manifest) {
        Entry::Vacant(entry) => {
            entry.insert((effect.identity(), bytes.to_vec()));
            Ok(())
        }
        Entry::Occupied(entry) => {
            let existing = entry.get();
            decode_memory_effect(existing).and_then(|stored| {
                (stored == *effect && existing.1.as_slice() == bytes)
                    .then_some(())
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
        }
    }
}

fn insert_index(
    map: &mut BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    request: ErasureReferenceV1,
    ordinal: u64,
    reference: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    insert_or_verify_staged(
        map,
        (request, ordinal),
        reference,
        ErasureErrorV1::PolicyConflict,
    )
}

fn memory_index_count(
    map: &BTreeMap<(ErasureReferenceV1, u64), ErasureReferenceV1>,
    request: ErasureReferenceV1,
) -> Result<u64, ErasureErrorV1> {
    u64::try_from(
        map.keys()
            .filter(|(candidate, _)| *candidate == request)
            .count(),
    )
    .map_err(|_| ErasureErrorV1::PolicyConflict)
}

impl OwnTracksEnrollmentStore for MemoryStore {
    fn pair_owntracks_enrollment(
        &mut self,
        request: OwnTracksEnrollmentRequestV1,
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.timeline(request.timeline())?;
        self.owntracks_enrollment = self.owntracks_enrollment.clone().pair(&request)?;
        Ok(self.owntracks_enrollment.status())
    }

    fn owntracks_enrollment_status(
        &self,
    ) -> Result<pos_core::OwnTracksEnrollmentStatusViewV1, CoreError> {
        Ok(self.owntracks_enrollment.status_view())
    }

    fn rotate_owntracks_enrollment_verifier(
        &mut self,
        verifier: [u8; 32],
    ) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.owntracks_enrollment = self.owntracks_enrollment.clone().rotate(verifier)?;
        Ok(self.owntracks_enrollment.status())
    }

    fn revoke_owntracks_enrollment(&mut self) -> Result<OwnTracksEnrollmentStatusV1, CoreError> {
        self.owntracks_enrollment = self.owntracks_enrollment.clone().revoke()?;
        Ok(self.owntracks_enrollment.status())
    }
}

impl OwnTracksIngressStore for MemoryStore {
    fn prepare_owntracks_ingress(
        &mut self,
        input: OwnTracksIngressInputV1,
    ) -> Result<PreparedOwnTracksIngressV1, CoreError> {
        self.owntracks_enrollment.prepare_owntracks_ingress(&input)
    }
}

impl GeoLocationAdmissionStore for MemoryStore {
    fn protected_logical_head(&self, timeline: TimelineId) -> Result<Seq, CoreError> {
        self.logical_head_unchecked(timeline)
    }

    fn admit_geo_location(
        &mut self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, CoreError> {
        let timeline = request.timeline();
        let entity = request.entity();
        let admitted_at = self.clock.now()?;
        let permits_request = |store: &Self| {
            store
                .owntracks_enrollment
                .permits_geographic_admission(&request)
        };

        if !permits_request(self) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }

        if let Some(record) = self
            .geographic_admission_dedup
            .get(&request.fingerprint())
            .copied()
            .filter(|record| record.expires_at > admitted_at)
        {
            return Ok(GeoLocationAdmissionOutcome::classify_retained_intent(
                request.intent(),
                record.intent,
                record.event_id,
            ));
        }

        let expires_at = checked_append_identity_expires_at(admitted_at)?;

        let draft = EventDraft::new(
            entity,
            Kind::new(GEOGRAPHIC_EVENT_TYPE),
            request.payload().clone(),
        )
        .with_wall_time(admitted_at);
        let event = {
            let (timelines, event_ids, hasher) =
                (&mut self.timelines, &mut self.event_ids, &self.hasher);
            mutable_state(timelines, timeline).and_then(|state| {
                let event = Self::append_one_to_state(state, &draft, hasher.as_ref())?;
                event_ids.insert(event.id);
                Ok(event)
            })?
        };
        let snapshot = request.snapshot().clone();
        let link =
            GeoLocationAdmissionLinkV1::for_snapshot(timeline, event.id, event.seq, &snapshot);

        self.geographic_timelines.insert(timeline);
        self.geographic_admission_snapshots
            .insert(event.id, snapshot);
        self.geographic_admission_links
            .insert((timeline, event.id), link);
        self.geographic_admission_dedup.insert(
            request.fingerprint(),
            GeographicAdmissionDedupRecord {
                timeline,
                intent: request.intent(),
                event_id: event.id,
                expires_at,
            },
        );
        Ok(GeoLocationAdmissionOutcome::accepted(event.id, event.seq))
    }
}

impl GeoLocationReplayVerifier for MemoryStore {
    fn verify_v1_event_snapshot_link(
        &self,
        evidence: GeoLocationReplayEvidenceV1,
    ) -> Result<(), CoreError> {
        let validation_failure = || Err(CoreError::GeographicAdmissionValidationFailed);
        let event = self.timelines.get(&evidence.timeline()).and_then(|state| {
            state
                .events
                .iter()
                .find(|event| event.id == evidence.event_id())
        });
        let Some(event) = event else {
            return validation_failure();
        };
        if event.seq != evidence.event_seq()
            || event.event_type.as_str() != GEOGRAPHIC_EVENT_TYPE
            || event.schema_version != pos_core::SchemaVersion::V1
            || event.payload_hash != evidence.event_payload_hash()
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return validation_failure();
        }
        let Some(snapshot) = self
            .geographic_admission_snapshots
            .get(&evidence.event_id())
        else {
            return validation_failure();
        };
        if snapshot.timeline() != evidence.timeline() || snapshot.entity() != event.entity {
            return validation_failure();
        }
        let Some(link) = self
            .geographic_admission_links
            .get(&(evidence.timeline(), evidence.event_id()))
        else {
            return validation_failure();
        };
        if link
            .validate_for(
                snapshot,
                evidence.timeline(),
                evidence.event_id(),
                evidence.event_seq(),
            )
            .is_err()
            || self.hasher.hash_payload(link.snapshot_cbor()) != evidence.snapshot_hash()
        {
            return validation_failure();
        }
        Ok(())
    }
}

impl GeographicAdmissionAdmin for MemoryStore {
    fn set_geo_cell_admission_consent_record(
        &mut self,
        record: AdmissionConsentRecordV1,
    ) -> Result<(), CoreError> {
        if AdmissionSnapshotId::from_canonical(record.id().as_str()).is_err()
            || record.revision() == 0
        {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let key = (record.id().clone(), record.revision());
        if let Some(existing) = self.geographic_cell_consent_records.get(&key) {
            if existing != &record {
                return Err(CoreError::GeographicAdmissionValidationFailed);
            }
            return Ok(());
        }
        self.geographic_cell_consent_records.insert(key, record);
        Ok(())
    }

    fn set_geo_cell_admission_fence(
        &mut self,
        timeline: TimelineId,
        entity: pos_core::EntityId,
        fence: GeoCellAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        if !self.timelines.contains_key(&timeline) {
            return Err(CoreError::TimelineNotFound(timeline));
        }
        if fence.draft().timeline() != timeline || fence.draft().entity() != entity {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        self.geographic_cell_fences
            .insert((timeline, entity), fence);
        Ok(())
    }
}

impl GeographicAdmissionConsentResolver for MemoryStore {
    fn resolve_admission_consent(
        &self,
        consent_record_id: &AdmissionSnapshotId,
        consent_revision: u64,
    ) -> Result<AdmissionConsentRecordV1, CoreError> {
        let record = self
            .geographic_cell_consent_records
            .get(&(consent_record_id.clone(), consent_revision))
            .cloned()
            .ok_or(CoreError::GeographicAdmissionValidationFailed)?;
        Ok(record)
    }
}

impl GeographicAdmissionStore for MemoryStore {
    #[allow(clippy::too_many_lines)]
    fn admit(
        &mut self,
        request: ValidatedGeographicAdmissionV1,
    ) -> Result<GeographicAdmissionOutcome, CoreError> {
        let timeline = request.timeline();
        let entity = request.entity();
        let Ok(admitted_at) = self.clock.now() else {
            return Ok(GeographicAdmissionOutcome::Unavailable);
        };
        let Some(fence) = self.geographic_cell_fences.get(&(timeline, entity)) else {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        };
        if !fence.permits(&request) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let consent_record = self.resolve_admission_consent(
            request.fence().draft().consent_record_id(),
            request.fence().draft().consent_revision(),
        )?;
        if !consent_record.matches_draft(request.fence().draft()) {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let mut staged_dedup = self.geographic_cell_dedup.clone();
        staged_dedup.retain(|_, record| record.expires_at > admitted_at);
        if let Some(record) = staged_dedup
            .get(&request.fingerprint())
            .filter(|record| record.expires_at > admitted_at)
            .cloned()
        {
            if record.intent.as_persistence_bytes() != request.intent().as_persistence_bytes() {
                self.geographic_cell_dedup = staged_dedup;
                return Ok(GeographicAdmissionOutcome::Conflict);
            }
            let outcome = self
                .verified_geo_cell_duplicate(&record)
                .unwrap_or(GeographicAdmissionOutcome::OutcomeUnknown);
            if !outcome.is_outcome_unknown() {
                self.geographic_cell_dedup = staged_dedup;
            }
            return Ok(outcome);
        }
        let Ok(expires_at) = pos_core::checked_append_identity_expires_at(admitted_at) else {
            return Ok(GeographicAdmissionOutcome::Unavailable);
        };
        let Some(existing_state) = self.timelines.get(&timeline) else {
            return Err(CoreError::TimelineNotFound(timeline));
        };
        let mut staged_state = existing_state.clone();
        let event_id = EventId::new();
        let event_seq = staged_state.timeline.head.next();
        let inherited_prefix = existing_state
            .timeline
            .meta
            .fork_point
            .map_or(0, |(_, fork)| fork.as_u64());
        let origin_logical_seq = crate::checked_logical_head(inherited_prefix, event_seq.as_u64())?;
        let snapshot_id = AdmissionSnapshotId::new();
        let snapshot =
            AdmissionEntitlementSnapshotV1::new(snapshot_id.clone(), &request, event_id, event_seq);
        let snapshot_cbor = snapshot.canonical_bytes();
        let snapshot_hash = snapshot.hash();
        let observation = request.payload(snapshot_id.clone(), snapshot_hash);
        let payload = observation.encode();
        let payload_hash = self.hasher.hash_payload(&payload);
        let event_id_bytes = event_id.to_string();
        let next_chain_head = self.hasher.hash_event(
            &staged_state.chain_head,
            event_id_bytes.as_bytes(),
            &payload,
        );
        let event = Event {
            id: event_id,
            entity,
            event_type: Kind::new(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE),
            payload,
            wall_time: admitted_at,
            seq: event_seq,
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: Some(EventOriginV1 {
                origin_timeline_id: timeline,
                origin_logical_seq: Seq::from_u64(origin_logical_seq),
            }),
            payload_hash,
        };
        staged_state.timeline.head = event_seq;
        staged_state.chain_head = next_chain_head;
        staged_state.events.push(event.clone());
        let link = GeographicCellLink {
            snapshot_id: snapshot_id.clone(),
            snapshot_hash,
            snapshot_cbor,
        };
        if self.hasher.hash_payload(&event.payload) != event.payload_hash {
            return Err(CoreError::GeographicAdmissionValidationFailed);
        }
        let dedup = GeographicCellDedupRecord {
            timeline,
            entity,
            intent: request.intent().clone(),
            event_id: event.id,
            event_seq: event.seq,
            snapshot_id: snapshot_id.clone(),
            snapshot_hash,
            expires_at,
        };
        self.timelines.insert(timeline, staged_state);
        self.event_ids.insert(event.id);
        self.geographic_timelines.insert(timeline);
        self.geographic_cell_snapshots
            .insert(snapshot_id.clone(), snapshot);
        self.geographic_cell_links
            .insert((timeline, event.id), link);
        staged_dedup.insert(request.fingerprint(), dedup);
        self.geographic_cell_dedup = staged_dedup;
        Ok(GeographicAdmissionOutcome::Accepted {
            persisted_event: Box::new(event.clone()),
            event_id: event.id,
            event_seq: event.seq,
            snapshot_id,
            snapshot_hash,
        })
    }
}

impl MemoryStore {
    fn verified_geo_cell_duplicate(
        &self,
        record: &GeographicCellDedupRecord,
    ) -> Option<GeographicAdmissionOutcome> {
        let state = self.timelines.get(&record.timeline)?;
        let event = state
            .events
            .iter()
            .find(|event| event.id == record.event_id)?;
        let record_event_seq = record.event_seq;
        if event.entity != record.entity
            || event.seq != record_event_seq
            || event.event_type.as_str() != pos_core::GEOGRAPHIC_CELL_EVENT_TYPE
            || event.schema_version != pos_core::SchemaVersion::V1
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return None;
        }
        let observation =
            pos_core::geo_cell_admission::GeographicObservationV1::decode(&event.payload).ok()?;
        if observation.snapshot_id() != &record.snapshot_id
            || observation.snapshot_hash() != record.snapshot_hash
        {
            return None;
        }
        let snapshot = self.geographic_cell_snapshots.get(&record.snapshot_id)?;
        let snapshot_cbor = snapshot.canonical_bytes();
        if snapshot.hash() != record.snapshot_hash
            || snapshot.event_id() != record.event_id
            || snapshot.event_seq() != record.event_seq
        {
            return None;
        }
        let linkage = snapshot.linkage();
        let consent = self
            .resolve_admission_consent(linkage.consent_record_id(), linkage.consent_revision())
            .ok()?;
        if !consent.matches_linkage(&linkage) {
            return None;
        }
        let link = self
            .geographic_cell_links
            .get(&(record.timeline, record.event_id))?;
        if link.snapshot_id != record.snapshot_id
            || link.snapshot_hash != record.snapshot_hash
            || link.snapshot_cbor != snapshot_cbor
        {
            return None;
        }
        Some(GeographicAdmissionOutcome::Duplicate {
            event_id: record.event_id,
            event_seq: record.event_seq,
            snapshot_id: record.snapshot_id.clone(),
            snapshot_hash: record.snapshot_hash,
        })
    }
}

impl GeographicReplayVerifier for MemoryStore {
    fn verify_geo_cell_event(&self, evidence: GeographicReplayEvidenceV1) -> Result<(), CoreError> {
        let fail = || Err(CoreError::GeographicAdmissionValidationFailed);
        let Some(state) = self.timelines.get(&evidence.timeline()) else {
            return fail();
        };
        let Some(event) = state
            .events
            .iter()
            .find(|event| event.id == evidence.event_id())
        else {
            return fail();
        };
        if event.seq != evidence.event_seq()
            || event.event_type.as_str() != pos_core::GEOGRAPHIC_CELL_EVENT_TYPE
            || event.schema_version != pos_core::SchemaVersion::V1
            || event.payload_hash != evidence.event_payload_hash()
            || self.hasher.hash_payload(&event.payload) != event.payload_hash
        {
            return fail();
        }
        let Ok(observation) =
            pos_core::geo_cell_admission::GeographicObservationV1::decode(&event.payload)
        else {
            return fail();
        };
        if observation.snapshot_id() != evidence.snapshot_id()
            || observation.snapshot_hash() != evidence.snapshot_hash()
        {
            return fail();
        }
        let Some(snapshot) = self.geographic_cell_snapshots.get(evidence.snapshot_id()) else {
            return fail();
        };
        let snapshot_cbor = snapshot.canonical_bytes();
        let evidence_snapshot_hash = evidence.snapshot_hash();
        if snapshot.hash() != evidence_snapshot_hash
            || snapshot.event_id() != evidence.event_id()
            || snapshot.event_seq() != evidence.event_seq()
            || snapshot.timeline() != evidence.timeline()
            || snapshot.entity() != event.entity
        {
            return fail();
        }
        let linkage = snapshot.linkage();
        let Ok(consent) =
            self.resolve_admission_consent(linkage.consent_record_id(), linkage.consent_revision())
        else {
            return fail();
        };
        if !consent.matches_linkage(&linkage) {
            return fail();
        }
        let Some(link) = self
            .geographic_cell_links
            .get(&(evidence.timeline(), evidence.event_id()))
        else {
            return fail();
        };
        if link.snapshot_id != *evidence.snapshot_id()
            || link.snapshot_hash != evidence.snapshot_hash()
            || link.snapshot_cbor != snapshot_cbor
        {
            return fail();
        }
        Ok(())
    }
}

impl MemoryStore {
    fn ensure_inventory_snapshot_limits(
        &self,
        limits: ErasureRecoveryLimitsV1,
    ) -> Result<(), ErasureErrorV1> {
        if limits.admits(self.erasure_records.len(), self.timelines.len()) {
            Ok(())
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    }

    const fn invalidate_inventory_generation_after_cas(
        &mut self,
        result: Result<ErasureCasOutcomeV1, ErasureErrorV1>,
    ) {
        if matches!(result, Ok(ErasureCasOutcomeV1::Applied)) {
            self.erasure_inventory_generation = None;
        }
    }

    fn ensure_key_registry_write_allowed(&self) -> Result<(), CoreError> {
        if let Some(gate) = self.erasure_gate.as_deref() {
            crate::validate_bound_erasure_inventory_generation(
                self.erasure_gate_bound,
                gate,
                self.erasure_inventory_generation,
            )?;
        } else if self.erasure_gate_bound {
            return Err(CoreError::ErasureContainmentUnavailable);
        }
        Ok(())
    }

    const fn ensure_direct_topology_mutation_allowed(&self) -> Result<(), CoreError> {
        if self.erasure_topology_requires_permit {
            Err(CoreError::ErasureContainmentUnavailable)
        } else {
            Ok(())
        }
    }

    fn with_direct_topology_mutation<T>(
        &mut self,
        effect: impl FnOnce(&mut Self) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        self.ensure_direct_topology_mutation_allowed()?;
        effect(self)
    }

    fn ensure_host_transition_permit(
        &self,
        permit: &ErasureTopologyTransitionPermitV1,
    ) -> Result<(), CoreError> {
        let (Some(gate), Some(binding)) = (
            self.erasure_gate.as_ref(),
            self.erasure_topology_store_binding.as_ref(),
        ) else {
            return Err(CoreError::ErasureContainmentUnavailable);
        };
        permit
            .claim_for_store(gate, binding)
            .then_some(())
            .ok_or(CoreError::ErasureContainmentUnavailable)
    }

    fn logical_head_unchecked(&self, id: TimelineId) -> Result<Seq, CoreError> {
        let chain = self.fork_chain(id)?;
        let mut logical_head = 0_u64;
        for (index, timeline) in chain.timelines.iter().enumerate() {
            let length = chain.segment_length(self, index, *timeline)?;
            logical_head = logical_head
                .checked_add(length)
                .ok_or_else(|| CoreError::Storage("logical Timeline head overflow".to_owned()))?;
        }
        Ok(Seq::from_u64(logical_head))
    }

    fn compute_chain_hash_at_unchecked(
        &self,
        timeline: TimelineId,
        at_seq: Seq,
    ) -> Result<Hash, CoreError> {
        self.compute_chain_hash_at_unchecked_impl(timeline, at_seq)
    }

    fn compute_chain_hash_at_unchecked_impl(
        &self,
        timeline: TimelineId,
        at_seq: Seq,
    ) -> Result<Hash, CoreError> {
        #[cfg(test)]
        if FAIL_NEXT_CHAIN_HASH_AT.with(|fail| fail.replace(false)) {
            return Err(CoreError::Storage(
                "injected chain-hash lookup failure".to_owned(),
            ));
        }
        let logical_head = self.logical_head_unchecked(timeline)?;
        if at_seq > logical_head {
            return Err(CoreError::ForkBeyondHead {
                fork_seq: at_seq.as_u64(),
                head: logical_head.as_u64(),
            });
        }
        let mut hash = self.hasher.genesis_hash();
        if at_seq == Seq::ZERO {
            return Ok(hash);
        }
        for event in
            self.collect_events_in_range(timeline, SeqRange::bounded(Seq::from_u64(1), at_seq))?
        {
            let id_str = event.id.to_string();
            hash = self
                .hasher
                .hash_event(&hash, id_str.as_bytes(), &event.payload);
        }
        Ok(hash)
    }

    fn create_timeline_with_meta_unchecked(
        &mut self,
        meta: &TimelineMeta,
    ) -> Result<Timeline, CoreError> {
        // Resolve fork parent before duplicate-id check (parity with SqliteStore).
        let chain = if let Some((parent, at_seq)) = meta.fork_point {
            self.ensure_generic_timeline_visibility(parent)
                .and_then(|()| {
                    let parent_head = self.logical_head_unchecked(parent)?;
                    if at_seq > parent_head {
                        Err(CoreError::ForkBeyondHead {
                            fork_seq: at_seq.as_u64(),
                            head: parent_head.as_u64(),
                        })
                    } else {
                        self.compute_chain_hash_at_unchecked(parent, at_seq)
                    }
                })
        } else {
            Ok(self.hasher.genesis_hash())
        }?;
        if self.timelines.contains_key(&meta.id) {
            return Err(CoreError::Storage(format!(
                "timeline already exists: {}",
                meta.id
            )));
        }
        let id = meta.id;
        let timeline = Timeline::new(meta.clone());
        self.timelines
            .insert(id, TimelineState::new(timeline.clone(), chain));
        Ok(timeline)
    }

    fn create_timeline_with_meta_with_erasure_fence(
        &mut self,
        meta: &TimelineMeta,
    ) -> Result<Timeline, CoreError> {
        match meta.fork_point {
            Some((parent, _)) => {
                self.with_erasure_fence(parent, ErasureProtectedOperationV1::Fork, |store| {
                    store.create_timeline_with_meta_unchecked(meta)
                })
            }
            None => self.create_timeline_with_meta_unchecked(meta),
        }
    }

    fn initialize_timeline_with_key_registry_for_host_transition_unchecked(
        &mut self,
        meta: &TimelineMeta,
        expected_registry: &KeyRegistryStateV1,
    ) -> Result<(Timeline, bool), CoreError> {
        let persisted = self.load_key_registry()?;
        if persisted
            .as_ref()
            .is_some_and(|current| current != expected_registry)
        {
            return Err(CoreError::Storage(
                "durable key registry changed during ledger initialization".to_owned(),
            ));
        }

        if let Some(timeline) = self
            .timelines
            .values()
            .map(|state| &state.timeline)
            .find(|timeline| timeline.meta.name == meta.name)
            .cloned()
        {
            if persisted.is_none() {
                self.save_key_registry_unchecked(expected_registry)?;
            }
            return Ok((timeline, false));
        }

        let timeline = self.create_timeline_with_meta_unchecked(meta)?;
        if persisted.is_some() {
            return Ok((timeline, true));
        }
        if let Err(error) = self.save_key_registry_unchecked(expected_registry) {
            return match delete_visible_timeline(self, timeline.id()) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(CoreError::StorageOutcomeUnknown(format!(
                    "ledger initialization failed ({error}); Timeline rollback also failed ({rollback_error})"
                ))),
            };
        }
        Ok((timeline, true))
    }

    fn save_key_registry_unchecked(
        &mut self,
        registry: &KeyRegistryStateV1,
    ) -> Result<(), CoreError> {
        registry
            .validate()
            .map_err(|error| CoreError::Serialization(error.to_string()))?;
        if let Some(previous) = &self.key_registry {
            previous
                .validate_replacement(registry)
                .map_err(|error| CoreError::Serialization(error.to_string()))?;
        }
        self.key_registry = Some(registry.clone());
        Ok(())
    }
}

impl MemoryStore {
    fn bind_erasure_gate_impl(
        &mut self,
        gate: Arc<ErasureContainmentGateV1>,
    ) -> Result<(), CoreError> {
        let binding = crate::issue_erasure_topology_store_binding(self.erasure_gate_bound, &gate)?;
        self.erasure_topology_requires_permit = binding.requires_transition_permit();
        self.erasure_inventory_generation = None;
        self.erasure_gate = Some(gate);
        self.erasure_topology_store_binding = Some(binding);
        self.erasure_gate_bound = true;
        Ok(())
    }
}

impl KeyRegistryHistoricalDecryptionPortV1 for MemoryStore {
    fn with_decryption_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T,
    {
        // The mutable store owner is held through the callback, as it is for
        // signing and destruction on this single-process adapter.
        identity
            .validate_historical_subject_decryption()
            .and_then(|()| {
                self.load_key_registry()
                    .map_err(|_| KeyRegistryErrorV1::RegistryUnavailable)
            })
            .and_then(|registry| registry.ok_or(KeyRegistryErrorV1::RegistryUnavailable))
            .and_then(|mut registry| {
                registry.with_decryption_authorization(identity, private_material_digest, operation)
            })
    }
}

impl EventStore for MemoryStore {
    fn commit_artifact_registration_batch(
        &mut self,
        batch: pos_core::PreparedArtifactRegistrationBatchV1,
    ) -> Result<
        pos_core::ArtifactRegistrationCommitOutcomeV1,
        pos_core::ArtifactRegistrationPersistenceErrorV1,
    > {
        ArtifactRegistrationPersistencePortV1::commit_artifact_registration_batch(self, batch)
    }

    fn read_artifact_registration(
        &self,
        owner_id: &pos_core::OwnerIdV1,
        registration_address: Hash,
    ) -> Result<
        Option<pos_core::ArtifactRegistrationCatalogRowV1>,
        pos_core::ArtifactRegistrationPersistenceErrorV1,
    > {
        ArtifactRegistrationPersistencePortV1::read_artifact_registration(
            self,
            owner_id,
            registration_address,
        )
    }

    fn adapter_recording_open_session(
        &mut self,
        session: AdapterRecordingSessionV1,
    ) -> Result<(), AdapterRecordingStoreErrorV1> {
        AdapterRecordingStoreV1::open_adapter_recording_session(self, session)
    }

    fn adapter_recording_reserve_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        reservation: AdapterCallReservationV1,
    ) -> Result<AdapterCallReservationOutcomeV1, AdapterRecordingStoreErrorV1> {
        AdapterRecordingStoreV1::reserve_adapter_call(
            self,
            owner_reference,
            run_operation_id,
            reservation,
        )
    }

    fn adapter_recording_complete_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        global_call_index: u64,
        output_bytes: Vec<u8>,
    ) -> Result<(), AdapterRecordingStoreErrorV1> {
        AdapterRecordingStoreV1::complete_adapter_call(
            self,
            owner_reference,
            run_operation_id,
            global_call_index,
            output_bytes,
        )
    }

    fn adapter_recording_close_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Vec<u8>, AdapterRecordingStoreErrorV1> {
        AdapterRecordingStoreV1::close_adapter_recording_session(
            self,
            owner_reference,
            run_operation_id,
        )
    }

    fn adapter_recording_read_closed_session(
        &self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Option<Vec<u8>>, AdapterRecordingStoreErrorV1> {
        AdapterRecordingStoreV1::read_closed_adapter_recording_session(
            self,
            owner_reference,
            run_operation_id,
        )
    }

    fn adapter_recording_abort_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<(), AdapterRecordingStoreErrorV1> {
        AdapterRecordingStoreV1::abort_adapter_recording_session(
            self,
            owner_reference,
            run_operation_id,
        )
    }

    fn bind_erasure_gate(&mut self, gate: Arc<ErasureContainmentGateV1>) -> Result<(), CoreError> {
        self.bind_erasure_gate_impl(gate)
    }

    fn bind_consent_authority(&mut self, permit: ConsentAppendPermit) -> Result<(), CoreError> {
        match self.consent_authority_permit {
            Some(existing) if existing != permit => Err(CoreError::Storage(
                "Gateway consent authority is already bound".to_owned(),
            )),
            Some(_) => Ok(()),
            None => {
                self.consent_authority_permit = Some(permit);
                Ok(())
            }
        }
    }

    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.with_direct_topology_mutation(|store| {
            let meta = TimelineMeta::root(name);
            let timeline = Timeline::new(meta);
            store.timelines.insert(
                timeline.id(),
                TimelineState::new(timeline.clone(), store.hasher.genesis_hash()),
            );
            Ok(timeline)
        })
    }

    fn create_timeline_for_host_transition_with_meta(
        &mut self,
        permit: &ErasureTopologyTransitionPermitV1,
        meta: TimelineMeta,
    ) -> Result<Timeline, CoreError> {
        self.ensure_host_transition_permit(permit)?;
        let timeline = self.create_timeline_with_meta_unchecked(&meta)?;
        self.erasure_inventory_generation = None;
        Ok(timeline)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            crate::ensure_non_geographic_drafts(drafts, timeline)
                .and_then(|()| store.ensure_generic_fork_append_is_rejected(timeline))
                .and_then(|()| store.ensure_generic_timeline_visibility(timeline))
                .and_then(|()| store.append_visible(timeline, drafts))
        })
    }

    fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, CoreError> {
        self.key_registry
            .as_ref()
            .map(|registry| {
                registry
                    .validate()
                    .map(|()| registry.clone())
                    .map_err(|error| CoreError::Serialization(error.to_string()))
            })
            .transpose()
    }

    fn save_key_registry(&mut self, registry: &KeyRegistryStateV1) -> Result<(), CoreError> {
        self.ensure_key_registry_write_allowed()
            .and_then(|()| self.save_key_registry_unchecked(registry))
    }

    fn initialize_timeline_with_key_registry_for_host_transition_with_meta(
        &mut self,
        permit: &ErasureTopologyTransitionPermitV1,
        meta: &TimelineMeta,
        expected_registry: &KeyRegistryStateV1,
    ) -> Result<(Timeline, bool), CoreError> {
        self.ensure_host_transition_permit(permit)?;
        let result = Self::initialize_timeline_with_key_registry_for_host_transition_unchecked(
            self,
            meta,
            expected_registry,
        );
        if matches!(
            &result,
            Ok((_, true)) | Err(CoreError::StorageOutcomeUnknown(_))
        ) {
            self.erasure_inventory_generation = None;
        }
        result
    }

    fn append_signed_authorized(
        &mut self,
        timeline: TimelineId,
        expected_registry: &KeyRegistryStateV1,
        create_event: &mut dyn FnMut(&KeyRegistryStateV1, Seq) -> Result<Event, CoreError>,
    ) -> Result<(), CoreError> {
        // A MemoryStore has one mutable owner; no second handle can change its
        // registry between this check and the all-or-nothing committed append.
        let persisted = self.checked_signing_registry(expected_registry)?;
        let head = self
            .get_timeline(timeline)?
            .ok_or(CoreError::TimelineNotFound(timeline))?;
        let event = create_event(&persisted, head.head.next())?;
        if event
            .signature_identity
            .is_some_and(|identity| identity.role == pos_core::KeyRoleV1::TimelineIntegritySigning)
        {
            return Err(CoreError::Storage(
                "Timeline signatures require the atomic envelope append seam".to_owned(),
            ));
        }
        self.append_committed(timeline, &[event])
    }

    fn append_timeline_signed_authorized(
        &mut self,
        timeline: TimelineId,
        expected_registry: &KeyRegistryStateV1,
        draft: EventDraft,
        identity: pos_core::KeyIdentityV1,
        material_digest: Hash,
        public_verification_key: pos_core::PublicKey,
        sign: &mut dyn FnMut(
            &mut KeyRegistryStateV1,
            &pos_core::TimelineEventEnvelopeV1,
            &pos_core::CanonicalBytes,
        ) -> Result<pos_core::Signature, CoreError>,
    ) -> Result<Event, CoreError> {
        let mut persisted = self.checked_signing_registry(expected_registry)?;
        let owning_timeline = self
            .get_timeline(timeline)
            .and_then(|head| head.ok_or(CoreError::TimelineNotFound(timeline)))?;
        let inherited_prefix = owning_timeline
            .meta
            .fork_point
            .map_or(0, |(_, at)| at.as_u64());
        let (mut event, envelope) = crate::prepare_timeline_signing_event(
            timeline,
            owning_timeline.head,
            inherited_prefix,
            draft,
            identity,
            self.hasher.as_ref(),
        )?;
        let mut signing_registry = persisted.clone();
        persisted
            .with_signing_authorization(identity, material_digest, public_verification_key, || {
                let signature = sign(&mut signing_registry, &envelope, &event.payload)?;
                crate::verify_new_timeline_signature(
                    public_verification_key,
                    identity,
                    &envelope,
                    &event.payload,
                    &signature,
                )?;
                event.signature = Some(signature);
                event.signature_identity = Some(identity);
                self.append_committed(timeline, std::slice::from_ref(&event))
                    .map(|()| event)
            })
            .map_err(|error| {
                CoreError::Storage(format!("Timeline signing authorization: {error}"))
            })?
    }

    fn append_prepared_subject_encrypted_timeline_signed(
        &mut self,
        timeline: TimelineId,
        expected_registry: &KeyRegistryStateV1,
        draft: EventDraft,
        authorization: pos_core::PreparedSubjectAppendAuthorizationV1,
        prepare_payload: &mut dyn FnMut(
            &pos_core::TimelineEventEnvelopeInputV1,
        ) -> Result<pos_core::CanonicalBytes, CoreError>,
        sign: &mut dyn FnMut(
            &mut KeyRegistryStateV1,
            &pos_core::TimelineEventEnvelopeV1,
            &pos_core::CanonicalBytes,
        ) -> Result<pos_core::Signature, CoreError>,
    ) -> Result<Event, CoreError> {
        // `&mut self` is the registry serialization boundary: no other handle
        // can rotate or destroy either identity until this call returns, so
        // concurrent lifecycle races are statically impossible here.
        self.checked_signing_registry(expected_registry)
            .and_then(|mut registry| {
                crate::prepare_subject_encrypted_timeline_event(
                    &*self,
                    self.hasher.as_ref(),
                    timeline,
                    &mut registry,
                    &draft,
                    &authorization,
                    crate::PreparedAppendCallbacks {
                        prepare_payload,
                        sign,
                    },
                )
            })
            .and_then(|event| {
                self.append_committed(timeline, std::slice::from_ref(&event))
                    .map(|()| event)
            })
    }

    fn begin_key_registry_destruction(
        &mut self,
        request: pos_core::KeyDestructionRequestV1,
    ) -> Result<(pos_core::KeyDestructionBeginOutcomeV1, KeyRegistryStateV1), CoreError> {
        let mut registry = self
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("key registry is unavailable".to_owned()))?;
        let outcome = registry
            .begin_key_destruction(request)
            .map_err(|error| CoreError::Storage(format!("key destruction: {error}")))?;
        self.save_key_registry(&registry)
            .map(|()| (outcome, registry))
    }

    fn complete_key_registry_destruction(
        &mut self,
        request: pos_core::KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<(pos_core::KeyDestructionOutcomeV1, KeyRegistryStateV1), CoreError> {
        let mut registry = self
            .load_key_registry()?
            .ok_or_else(|| CoreError::Storage("key registry is unavailable".to_owned()))?;
        let outcome = registry
            .complete_key_destruction(request, deletion_receipt)
            .map_err(|error| CoreError::Storage(format!("key destruction: {error}")))?;
        self.save_key_registry(&registry)
            .map(|()| (outcome, registry))
    }

    fn append_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        max_owned_events: u64,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            store.append_bounded_with_boundary(
                timeline,
                drafts,
                max_owned_events,
                false,
                None,
                None,
            )
        })
    }

    fn append_consent_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        max_owned_events: u64,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            store.append_bounded_with_boundary(
                timeline,
                drafts,
                max_owned_events,
                true,
                Some(permit),
                None,
            )
        })
    }

    fn append_consent_revocation_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        max_owned_events: u64,
        cleanup_scope: AppendDedupScope,
    ) -> Result<Option<Vec<Event>>, CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            crate::ensure_gateway_consent_revocation(drafts, timeline).and_then(|()| {
                store.append_bounded_with_boundary(
                    timeline,
                    drafts,
                    max_owned_events,
                    true,
                    Some(permit),
                    Some(cleanup_scope),
                )
            })
        })
    }

    fn append_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        admitted_at: WallTime,
        draft: EventDraft,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            store
                .append_or_duplicate_with_limit(timeline, identity, admitted_at, &draft, None)
                .and_then(crate::unbounded_append_outcome)
        })
    }

    fn purge_expired_append_identities(&mut self, now: WallTime) -> Result<usize, CoreError> {
        let before = self.append_identities.len();
        self.append_identities
            .retain(|_, record| record.expires_at > now);
        Ok(before.saturating_sub(self.append_identities.len()))
    }

    fn append_intent_or_duplicate(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
    ) -> Result<AppendOrDuplicateOutcome, CoreError> {
        let admitted_at = self.clock.now()?;
        let mut draft = intent.into_draft();
        draft.wall_time = Some(admitted_at);
        self.append_or_duplicate(timeline, identity, admitted_at, draft)
    }

    fn append_intent_or_duplicate_bounded(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        max_owned_events: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
        let admitted_at = self.clock.now()?;
        let mut draft = intent.into_draft();
        draft.wall_time = Some(admitted_at);
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            store.append_or_duplicate_with_limit(
                timeline,
                identity,
                admitted_at,
                &draft,
                Some(max_owned_events),
            )
        })
    }

    fn read_event_by_id(
        &self,
        timeline: TimelineId,
        event_id: EventId,
    ) -> Result<Option<Event>, CoreError> {
        self.with_erasure_read_fence(timeline, ErasureProtectedOperationV1::Read, |store| {
            read_event_by_id(store, timeline, event_id)
        })
    }

    fn purge_expired_append_identities_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        let now = self.clock.now()?;
        let mut expired: Vec<_> = self
            .append_identities
            .iter()
            .filter(|(_, record)| record.expires_at <= now)
            .map(|(key, record)| (record.expires_at, *key))
            .collect();
        expired.sort_unstable_by_key(|(expires_at, key)| (*expires_at, key.as_bytes()));
        let more_may_remain = expired.len() > limit.get();
        let removed = expired.len().min(limit.get());
        for (_, key) in expired.into_iter().take(removed) {
            self.append_identities.remove(&key);
        }
        Ok(PurgeOutcome {
            removed,
            more_may_remain,
        })
    }

    fn remove_append_identities(&mut self, scope: AppendDedupScope) -> Result<usize, CoreError> {
        let before = self.append_identities.len();
        self.append_identities
            .retain(|_, record| record.scope != scope);
        self.pending_append_identity_cleanup
            .retain(|pending| *pending != scope);
        Ok(before.saturating_sub(self.append_identities.len()))
    }

    fn remove_append_identities_bounded(
        &mut self,
        scope: AppendDedupScope,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        // Admitted-batch receipts share the subject-scoped cleanup group, so a
        // consent revocation also releases the subject's action retry keys.
        let mut matching: Vec<_> = self
            .append_identities
            .iter()
            .filter(|(_, record)| record.scope == scope)
            .map(|(key, record)| (record.expires_at, *key))
            .chain(
                self.pipeline_admission_receipts
                    .iter()
                    .filter(|(_, record)| record.scope == scope)
                    .map(|(key, record)| (record.expires_at, *key)),
            )
            .collect();
        matching.sort_unstable_by_key(|(expires_at, key)| (*expires_at, key.as_bytes()));
        let more_may_remain = matching.len() > limit.get();
        let removed = matching.len().min(limit.get());
        for (_, key) in matching.into_iter().take(removed) {
            self.append_identities.remove(&key);
            self.pipeline_admission_receipts.remove(&key);
        }
        if more_may_remain {
            if !self.pending_append_identity_cleanup.contains(&scope) {
                self.pending_append_identity_cleanup.push(scope);
            }
        } else {
            self.pending_append_identity_cleanup
                .retain(|pending| *pending != scope);
        }
        Ok(PurgeOutcome {
            removed,
            more_may_remain,
        })
    }

    fn pending_append_identity_cleanup(&mut self) -> Result<Option<AppendDedupScope>, CoreError> {
        Ok(self.pending_append_identity_cleanup.last().copied())
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.with_erasure_read_fence(timeline, ErasureProtectedOperationV1::Read, |store| {
            store
                .ensure_generic_timeline_visibility(timeline)
                .and_then(|()| store.collect_events_in_range(timeline, range))
        })
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.with_erasure_read_fence(timeline, ErasureProtectedOperationV1::Read, |store| {
            store
                .ensure_generic_timeline_visibility(timeline)
                .and_then(|()| store.collect_events_in_range_bounded(timeline, range, bounds))
        })
    }

    fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.with_erasure_read_fence(timeline, ErasureProtectedOperationV1::Export, |store| {
            read_own(store, timeline, range)
        })
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.with_direct_topology_mutation(|store| {
            store.with_erasure_fence(parent, ErasureProtectedOperationV1::Fork, |store| {
                store
                    .ensure_generic_timeline_visibility(parent)
                    .and_then(|()| store.fork_timeline_unchecked(parent, at_seq, name))
            })
        })
    }

    fn fork_for_host_transition_with_meta(
        &mut self,
        permit: &ErasureTopologyTransitionPermitV1,
        parent: TimelineId,
        at_seq: Seq,
        meta: TimelineMeta,
    ) -> Result<Timeline, CoreError> {
        self.ensure_host_transition_permit(permit)?;
        if meta.fork_point != Some((parent, at_seq)) {
            return Err(CoreError::Storage(
                "preallocated Fork metadata does not match the requested parent and sequence"
                    .to_owned(),
            ));
        }
        let result = self
            .ensure_generic_timeline_visibility(parent)
            .and_then(|()| self.create_timeline_with_meta_unchecked(&meta));
        if crate::inventory_generation_may_have_changed(&result) {
            self.erasure_inventory_generation = None;
        }
        result
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.timelines
            .values()
            .map(|state| self.visible_timeline_for_read(&state.timeline))
            .collect::<Result<Vec<_>, _>>()
            .map(|timelines| timelines.into_iter().flatten().collect())
    }

    fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
        self.count_visible_root_timeline_ids(
            maximum,
            self.timelines
                .values()
                .filter(|state| state.timeline.meta.is_root())
                .map(|state| state.timeline.id()),
        )
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        self.with_erasure_read_fence(id, ErasureProtectedOperationV1::Read, |store| {
            store.timelines.get(&id).map_or(Ok(None), |state| {
                crate::generic_timeline_is_visible(Ok(store.geographic_timelines.contains(&id)))
                    .map(|visible| visible.then(|| state.timeline.clone()))
            })
        })
    }

    fn get_timeline_for_host_transition(
        &self,
        permit: &ErasureTopologyTransitionPermitV1,
        id: TimelineId,
    ) -> Result<Option<Timeline>, CoreError> {
        self.ensure_host_transition_permit(permit)?;
        Ok(self.timelines.get(&id).map(|state| state.timeline.clone()))
    }

    fn find_timeline_by_name_for_host_transition(
        &self,
        permit: &ErasureTopologyTransitionPermitV1,
        name: &str,
    ) -> Result<Option<Timeline>, CoreError> {
        self.ensure_host_transition_permit(permit)?;
        Ok(self
            .timelines
            .values()
            .find(|state| state.timeline.meta.name.as_deref() == Some(name))
            .map(|state| state.timeline.clone()))
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        self.with_erasure_read_fence(id, ErasureProtectedOperationV1::Read, |store| {
            store
                .ensure_generic_timeline_visibility(id)
                .and_then(|()| store.logical_head_unchecked(id))
        })
    }

    fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
        self.with_direct_topology_mutation(|store| {
            store.create_timeline_with_meta_with_erasure_fence(&meta)
        })
    }

    fn append_committed(
        &mut self,
        timeline: TimelineId,
        events: &[Event],
    ) -> Result<(), CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            crate::ensure_non_geographic_events(events, timeline)
                .and_then(|()| store.ensure_generic_fork_append_is_rejected(timeline))
                .and_then(|()| store.ensure_generic_timeline_visibility(timeline))
                .and_then(|()| {
                    if events.is_empty() {
                        return Ok(());
                    }

                    let mut timeline_state = store.state(timeline).timeline.clone();
                    let head = timeline_state.head;
                    let mut ordered = pos_core::store::validate_committed_batch(
                        head,
                        events,
                        &mut |id| store.event_ids.contains(id),
                        &*store.hasher,
                    )?;
                    crate::finalize_committed_origins(
                        timeline,
                        timeline_state
                            .meta
                            .fork_point
                            .map_or(0, |(_, fork)| fork.as_u64()),
                        &mut ordered,
                    )?;
                    let mut new_head = head;
                    let mut previous_hash = store.chain_head(timeline);
                    for event in &ordered {
                        let id_str = event.id.to_string();
                        previous_hash = store.hasher.hash_event(
                            &previous_hash,
                            id_str.as_bytes(),
                            &event.payload,
                        );
                        new_head = event.seq;
                    }

                    store.event_ids.extend(ordered.iter().map(|event| event.id));
                    store.state_mut(timeline).map(|state| {
                        state.events.extend(ordered);
                        timeline_state.head = new_head;
                        state.timeline = timeline_state;
                        state.chain_head = previous_hash;
                    })
                })
        })
    }

    fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
        self.with_direct_topology_mutation(|store| delete_timeline(store, id))
    }

    fn chain_hash_at(&self, timeline: TimelineId, at_seq: Seq) -> Result<Hash, CoreError> {
        self.with_erasure_read_fence(timeline, ErasureProtectedOperationV1::Export, |store| {
            store
                .ensure_generic_timeline_visibility(timeline)
                .and_then(|()| store.compute_chain_hash_at(timeline, at_seq))
        })
    }

    fn import_committed(
        &mut self,
        meta: TimelineMeta,
        events: &[Event],
    ) -> Result<Timeline, CoreError> {
        self.with_direct_topology_mutation(|store| {
            pos_core::store::import_committed_with_rollback(store, meta, events)
        })
    }
}

impl MemoryStore {
    /// ADR-099 reserves every admitted Fork's append boundary for its
    /// classifier authority.  Generic callers never obtain a bypass.
    fn ensure_generic_fork_append_is_rejected(
        &self,
        timeline: TimelineId,
    ) -> Result<(), CoreError> {
        if self.fork_admissions.contains_key(&timeline) {
            return Err(CoreError::Storage(
                "admitted Fork Events require classified append authority".to_owned(),
            ));
        }
        Ok(())
    }
}

impl MemoryStore {
    /// Compute the hash chain value at a specific seq in a timeline.
    fn compute_chain_hash_at(&self, timeline: TimelineId, at_seq: Seq) -> Result<Hash, CoreError> {
        self.compute_chain_hash_at_unchecked(timeline, at_seq)
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum TestCorruption {
    ForkParent {
        timeline: TimelineId,
        parent: TimelineId,
        fork_seq: Seq,
    },
}

#[cfg(test)]
impl MemoryStore {
    fn test_corrupt(&mut self, corruption: TestCorruption) {
        match corruption {
            TestCorruption::ForkParent {
                timeline,
                parent,
                fork_seq,
            } => {
                self.timelines
                    .get_mut(&timeline)
                    .unwrap_or_else(|| {
                        std::panic::resume_unwind(Box::new(
                            "test corruption targets an existing Timeline",
                        ))
                    })
                    .timeline
                    .meta
                    .fork_point = Some((parent, fork_seq));
            }
        }
    }

    fn test_corrupt_recovery_error_index(
        &mut self,
        request: ErasureReferenceV1,
        highest_ordinal: usize,
    ) {
        for ordinal in 0..=highest_ordinal {
            let mut digest = [0_u8; 32];
            let ordinal = u64::try_from(ordinal).unwrap_or(u64::MAX);
            digest[..8].copy_from_slice(&ordinal.to_be_bytes());
            self.erasure_recovery_errors
                .entry(request)
                .or_default()
                .insert(ErasureReferenceV1::from_digest(digest));
        }
    }

    pub(crate) fn test_remove_timeline(&mut self, id: TimelineId) {
        self.timelines.remove(&id);
        self.geographic_timelines.remove(&id);
    }

    pub(crate) fn test_remove_fork_classifier_table(&mut self, child: TimelineId) {
        let _ = self.fork_classifier_tables.remove(&child);
    }

    pub(crate) fn test_remove_fork_classifier_registration(&mut self, child: TimelineId) {
        self.fork_classifier_registrations
            .retain(|_, record| record.input().child_timeline_id != child);
    }

    pub(crate) fn test_remove_fork_classifier_source(&mut self, room: Hash, registrar: &str) {
        let _ = self
            .fork_classifier_sources
            .remove(&(room, registrar.to_owned()));
    }

    /// Tamper the committed Timeline Event that one classified FOP1 binds.
    pub(crate) fn test_tamper_classified_event(
        &mut self,
        operation_id: Hash,
        tamper: fn(&mut Event),
    ) {
        let event_id = self
            .fork_append_operations
            .get(&operation_id)
            .map(|operation| operation.input().event_id);
        self.timelines
            .values_mut()
            .flat_map(|state| state.events.iter_mut())
            .filter(|event| Some(event.id) == event_id)
            .for_each(tamper);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ErasureRejoinPersistencePortV1;
    use ciborium::value::Value;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        fork_authentication::{
            principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
            ForkAuthenticationPolicyV1,
        },
        geo_admission::{
            GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1,
            GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore, GeoLocationReplayEvidenceV1,
            GeoLocationReplayVerifier,
        },
        geo_cell_admission::{
            hash_admission_consent_record_bytes, AdmissionConsentRecordV1,
            AdmissionEntitlementDraftV1, AdmissionEntitlementSnapshotV1, AdmissionSnapshotHash,
            AdmissionSnapshotId, GeoCellAdmissionFenceV1, GeoCellAdmissionInputV1,
            GeoCellAdmissionRequestV1, GeographicAdmissionAdmin, GeographicAdmissionStore,
            ValidatedGeoCellV1,
        },
        ids::{EntityId, EventId},
        store::{SeqRange, TimelineExport},
        ErasureVerifiedEmptyInventoryQueryV1, ErasureVerifiedInventoryQueryV1,
        ErasureVerifiedInventoryV1, EventOriginRecordInputV1, ForkAdmissionHostCommandV1,
        ForkAppendOperationInputV1, ForkAppendSourceIdentityV1, ForkClassifierSourceInputV1,
        ForkClassifierTableInputV1, ForkEventOriginKindV1, ForkInterventionAdmissionInputV1,
        KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1,
        OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStore, OwnerIdV1, PrincipalRefV1,
        PublicKey,
    };
    use pos_crypto::fork_authentication::{
        verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
        ForkHostSigningKeyV1,
    };

    #[test]
    fn fork_admission_error_mapping_and_incomplete_graph_fail_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let row = ForkAdmissionOperationRowV1 {
            kind: ForkAdmissionOperationKindV1::Fork,
            operation_id: Hash::from_bytes([1; 32]),
            evidence_digest: Hash::from_bytes([2; 32]),
            commitment: Hash::from_bytes([3; 32]),
            result_digest: Hash::from_bytes([4; 32]),
            child_id: None,
        };
        assert_eq!(
            MemoryStore::new().stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let mut store = MemoryStore::new();
        let operation_id = Hash::from_bytes([5; 32]);
        store.fork_admission_authority.host = Some(ForkAdmissionHostRecordV1::new(
            Hash::from_bytes([6; 32]),
            PublicKey::from_bytes([7; 32]),
            Hash::from_bytes([8; 32]),
        )?);
        let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id,
            principal_digest: Hash::from_bytes([9; 32]),
            owner: pos_core::OwnerIdV1::new("owner")?,
            origin: ForkAuthorityOriginV1::Local,
        })?;
        store
            .fork_principal_owner_bindings
            .insert(Hash::from_bytes([9; 32]), binding);
        assert_eq!(
            store.stored_fork_admission_result(&ForkAdmissionOperationRowV1 {
                kind: ForkAdmissionOperationKindV1::PrincipalOwner,
                operation_id,
                evidence_digest: Hash::from_bytes([10; 32]),
                commitment: Hash::from_bytes([11; 32]),
                result_digest: Hash::zero(),
                child_id: None,
            }),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        // Committed corruption precedes Conflict for an unequal FAC1 reuse.
        assert_eq!(
            store.exact_fork_admission_result(
                &ForkAdmissionOperationRowV1 {
                    kind: ForkAdmissionOperationKindV1::PrincipalOwner,
                    operation_id,
                    evidence_digest: Hash::from_bytes([10; 32]),
                    commitment: Hash::from_bytes([11; 32]),
                    result_digest: Hash::zero(),
                    child_id: None,
                },
                &VerifiedForkAdmissionCommandV1::PrincipalOwner {
                    operation_id,
                    evidence_digest: Hash::from_bytes([15; 32]),
                    principal_digest: Hash::from_bytes([9; 32]),
                    owner: pos_core::OwnerIdV1::new("other-owner")?,
                    commitment: Hash::from_bytes([16; 32]),
                    issued_at: 0,
                    expires_at: 1,
                },
            ),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        assert_eq!(
            store.stored_fork_admission_result(&ForkAdmissionOperationRowV1 {
                kind: ForkAdmissionOperationKindV1::Fork,
                operation_id,
                evidence_digest: Hash::from_bytes([12; 32]),
                commitment: Hash::from_bytes([13; 32]),
                result_digest: Hash::from_bytes([14; 32]),
                child_id: None,
            }),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    #[test]
    fn fork_admission_memory_rejects_missing_durable_prerequisites(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let hash = |value| Hash::from_bytes([value; 32]);
        let operation_id = hash(31);
        let mut store = MemoryStore::new();
        let command = MemoryForkAdmissionOperation {
            operation_id,
            evidence_digest: hash(32),
            principal_digest: hash(33),
            parent_id: TimelineId::new(),
            cut: 0,
            descriptor_hash: hash(34),
            composition_hash: hash(35),
            attribution_required: false,
            child_name: "child".to_owned(),
            commitment: hash(36),
        };
        assert_eq!(
            store.execute_fork_admission_fork_command(
                (ForkAdmissionOperationKindV1::Fork, operation_id),
                command,
                Ok(()),
            ),
            Err(pos_core::ForkAdmissionErrorV1::InvalidRequest)
        );
        store.fork_admission_authority.host = Some(ForkAdmissionHostRecordV1::new(
            hash(37),
            PublicKey::from_bytes([38; 32]),
            hash(39),
        )?);
        assert_eq!(
            store.stored_fork_admission_result(&ForkAdmissionOperationRowV1 {
                kind: ForkAdmissionOperationKindV1::PrincipalOwner,
                operation_id,
                evidence_digest: hash(40),
                commitment: hash(41),
                result_digest: hash(42),
                child_id: None,
            }),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    fn memory_principal_owner_operation(
    ) -> Result<(MemoryStore, ForkAdmissionOperationRowV1), Box<dyn std::error::Error>> {
        let hash = |value| Hash::from_bytes([value; 32]);
        let host =
            ForkAdmissionHostRecordV1::new(hash(43), PublicKey::from_bytes([44; 32]), hash(45))?;
        let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id: hash(46),
            principal_digest: hash(47),
            owner: pos_core::OwnerIdV1::new("owner")?,
            origin: ForkAuthorityOriginV1::Local,
        })?;
        let evidence_digest = hash(48);
        let row = ForkAdmissionOperationRowV1 {
            kind: ForkAdmissionOperationKindV1::PrincipalOwner,
            operation_id: binding.input().operation_id,
            evidence_digest,
            commitment: principal_owner_commitment(host.store_id(), &binding, evidence_digest),
            result_digest: binding.digest(),
            child_id: None,
        };
        let mut store = MemoryStore::new();
        store.fork_admission_authority.host = Some(host);
        insert_test_binding(&mut store, binding);
        Ok((store, row))
    }

    #[test]
    fn fork_admission_memory_recovery_rejects_corrupt_principal_owner_operation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (store, row) = memory_principal_owner_operation()?;
        assert!(store.stored_fork_admission_result(&row).is_ok());

        let (mut store, row) = memory_principal_owner_operation()?;
        store.fork_principal_owner_bindings.clear();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (store, mut row) = memory_principal_owner_operation()?;
        row.result_digest = Hash::zero();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (store, mut row) = memory_principal_owner_operation()?;
        row.commitment = Hash::zero();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (store, mut row) = memory_principal_owner_operation()?;
        row.child_id = Some(TimelineId::new());
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    #[test]
    fn fork_admission_memory_maps_chain_hash_failure_to_parent_changed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let hash = |value| Hash::from_bytes([value; 32]);
        let mut store = MemoryStore::new();
        let parent = store.create_timeline("parent")?;
        let principal_digest = hash(43);
        store.fork_principal_owner_bindings.insert(
            principal_digest,
            PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
                operation_id: hash(44),
                principal_digest,
                owner: pos_core::OwnerIdV1::new("owner")?,
                origin: ForkAuthorityOriginV1::Local,
            })?,
        );
        fail_next_chain_hash_at_for_test();
        assert_eq!(
            store.execute_fork_admission_fork_command(
                (ForkAdmissionOperationKindV1::Fork, hash(45)),
                MemoryForkAdmissionOperation {
                    operation_id: hash(45),
                    evidence_digest: hash(46),
                    principal_digest,
                    parent_id: parent.id(),
                    cut: 0,
                    descriptor_hash: hash(47),
                    composition_hash: hash(48),
                    attribution_required: false,
                    child_name: "child".to_owned(),
                    commitment: hash(49),
                },
                Ok(()),
            ),
            Err(pos_core::ForkAdmissionErrorV1::ParentChanged)
        );
        Ok(())
    }

    fn insert_test_binding(store: &mut MemoryStore, binding: PrincipalOwnerBindingV1) {
        store
            .fork_principal_owner_binding_digests
            .insert(binding.digest(), binding.input().principal_digest);
        store
            .fork_principal_owner_bindings
            .insert(binding.input().principal_digest, binding);
    }

    fn memory_fork_admission_graph(
        creator: &str,
    ) -> Result<(MemoryStore, ForkAdmissionOperationRowV1), Box<dyn std::error::Error>> {
        let hash = |value| Hash::from_bytes([value; 32]);
        let host =
            ForkAdmissionHostRecordV1::new(hash(51), PublicKey::from_bytes([52; 32]), hash(53))?;
        let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id: hash(54),
            principal_digest: hash(55),
            owner: pos_core::OwnerIdV1::new("owner")?,
            origin: ForkAuthorityOriginV1::Local,
        })?;
        let mut store = MemoryStore::new();
        let parent_timeline = Timeline::new(TimelineMeta::root("parent"));
        let parent = parent_timeline.id();
        let parent_chain_head = store.hasher.genesis_hash();
        store.timelines.insert(
            parent,
            TimelineState::new(parent_timeline, parent_chain_head),
        );
        let child = Timeline::new(TimelineMeta::forked_from(parent, Seq::ZERO, "child"));
        let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
            operation_id: hash(56),
            principal_owner_binding_digest: binding.digest(),
            creator: pos_core::OwnerIdV1::new(creator)?,
            parent_timeline_id: parent,
            child_timeline_id: child.id(),
            room_revision_descriptor_hash: hash(57),
            parent_logical_head: 0,
            parent_chain_head_hash: parent_chain_head,
            completed_fold_cursor: 0,
            post_fold_tick_boundary: 0,
            plugin_composition_hash: hash(59),
            attribution_required: false,
            origin: ForkAttributionOriginV1::Local,
        })?;
        let evidence_digest = hash(60);
        let row = ForkAdmissionOperationRowV1 {
            kind: ForkAdmissionOperationKindV1::Fork,
            operation_id: admission.input().operation_id,
            evidence_digest,
            commitment: fork_commitment(
                host.store_id(),
                binding.input().principal_digest,
                evidence_digest,
                &admission,
                "child",
            ),
            result_digest: admission.digest(),
            child_id: Some(child.id()),
        };
        let binding_key = (
            ForkAdmissionOperationKindV1::PrincipalOwner,
            binding.input().operation_id,
        );
        store.fork_admission_operations.insert(
            binding_key,
            ForkAdmissionOperationRowV1 {
                kind: ForkAdmissionOperationKindV1::PrincipalOwner,
                operation_id: binding.input().operation_id,
                evidence_digest: hash(61),
                commitment: principal_owner_commitment(host.store_id(), &binding, hash(61)),
                result_digest: binding.digest(),
                child_id: None,
            },
        );
        store.fork_admission_authority.host = Some(host);
        insert_test_binding(&mut store, binding);
        store.fork_admissions.insert(child.id(), admission);
        store
            .timelines
            .insert(child.id(), TimelineState::new(child, parent_chain_head));
        Ok((store, row))
    }

    #[test]
    fn fork_admission_memory_rejects_each_missing_fork_graph_edge(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (store, row) = memory_fork_admission_graph("owner")?;
        let _ = store.stored_fork_admission_result(&row)?;

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        store.fork_admissions.clear();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        store.fork_principal_owner_bindings.clear();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        let child_id = row
            .child_id
            .ok_or_else(|| std::io::Error::other("missing child fixture"))?;
        let parent_id = store
            .fork_admissions
            .get(&child_id)
            .map(|admission| admission.input().parent_timeline_id)
            .ok_or_else(|| std::io::Error::other("missing Fork admission fixture"))?;
        store.timelines.remove(&parent_id);
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        store.timelines.clear();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, mut row) = memory_fork_admission_graph("owner")?;
        let child_id = row
            .child_id
            .ok_or_else(|| std::io::Error::other("missing child fixture"))?;
        let admission = store
            .fork_admissions
            .get(&child_id)
            .cloned()
            .ok_or_else(|| std::io::Error::other("missing Fork admission fixture"))?;
        let mut input = admission.input().clone();
        input.parent_chain_head_hash = Hash::from_bytes([81; 32]);
        let corrupt_admission = ForkAdmissionRecordV1::new(input)?;
        let binding = store
            .principal_owner_binding_by_digest(admission.input().principal_owner_binding_digest)
            .ok_or_else(|| std::io::Error::other("missing Principal-to-Owner fixture"))?;
        let store_id = store
            .fork_admission_authority
            .host
            .ok_or_else(|| std::io::Error::other("missing host fixture"))?
            .store_id();
        row.result_digest = corrupt_admission.digest();
        row.commitment = fork_commitment(
            store_id,
            binding.input().principal_digest,
            row.evidence_digest,
            &corrupt_admission,
            "child",
        );
        store.fork_admissions.insert(child_id, corrupt_admission);
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        Ok(())
    }

    #[test]
    fn fork_admission_memory_rejects_corrupt_fork_rows_and_child_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (store, mut row) = memory_fork_admission_graph("owner")?;
        row.result_digest = Hash::zero();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (store, mut row) = memory_fork_admission_graph("owner")?;
        row.commitment = Hash::zero();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (store, row) = memory_fork_admission_graph("other-owner")?;
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        let child_id = row
            .child_id
            .ok_or_else(|| std::io::Error::other("missing child fixture"))?;
        let child = store
            .timelines
            .get_mut(&child_id)
            .ok_or_else(|| std::io::Error::other("missing timeline fixture"))?;
        child.timeline.meta.fork_point = None;
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        let child_id = row
            .child_id
            .ok_or_else(|| std::io::Error::other("missing child fixture"))?;
        let child = store
            .timelines
            .get_mut(&child_id)
            .ok_or_else(|| std::io::Error::other("missing timeline fixture"))?;
        child.timeline.meta.name = None;
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (store, mut row) = memory_fork_admission_graph("owner")?;
        row.child_id = None;
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    /// ADR-099: an orphan `FPO1` or `FPB1` carrying a record ID occupies it,
    /// and an unrelated record ID stays free.
    #[test]
    fn fork_publication_record_is_present_checks_operations_and_bindings(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let child_timeline_id = TimelineId::new();
        let record_id = Hash::from_bytes([21; 32]);
        let operation =
            ForkPublicationOperationV1::new(pos_core::ForkPublicationOperationInputV1 {
                operation_id: Hash::from_bytes([22; 32]),
                child_timeline_id,
                final_logical_head: 0,
                final_chain_head_hash: Hash::zero(),
                admission_digest: Hash::from_bytes([23; 32]),
                signing_identity: KeyIdentityV1::new(
                    "publisher",
                    KeyRoleV1::SubjectAttributionSigning,
                    1,
                ),
                private_material_digest: Hash::from_bytes([24; 32]),
                public_verification_key: PublicKey::from_bytes([25; 32]),
                signed_manifest_record_id: record_id,
                origin: ForkAttributionOriginV1::Local,
            })?;
        let binding = ForkPublicationBindingV1::new(pos_core::ForkPublicationBindingInputV1 {
            child_timeline_id,
            final_logical_head: 7,
            operation_id: Hash::from_bytes([26; 32]),
            signed_manifest_record_id: record_id,
        })?;
        let miss = Hash::from_bytes([27; 32]);

        let mut by_operation = MemoryStore::new();
        assert!(!by_operation.fork_publication_record_is_present(record_id));
        by_operation
            .fork_publication_operations
            .insert(operation.input().operation_id, operation);
        assert!(by_operation.fork_publication_record_is_present(record_id));
        assert!(!by_operation.fork_publication_record_is_present(miss));

        let mut by_binding = MemoryStore::new();
        by_binding
            .fork_publication_bindings
            .insert((child_timeline_id, 7), binding);
        assert!(by_binding.fork_publication_record_is_present(record_id));
        assert!(!by_binding.fork_publication_record_is_present(miss));
        Ok(())
    }

    #[test]
    fn fork_admission_memory_rejects_an_orphaned_principal_owner_binding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut store, row) = memory_fork_admission_graph("owner")?;
        store
            .fork_admission_operations
            .retain(|(kind, _), _| *kind != ForkAdmissionOperationKindV1::PrincipalOwner);
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        for binding_row in store.fork_admission_operations.values_mut() {
            if binding_row.kind == ForkAdmissionOperationKindV1::PrincipalOwner {
                binding_row.child_id = row.child_id;
            }
        }
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );

        let (mut store, row) = memory_fork_admission_graph("owner")?;
        store.fork_principal_owner_binding_digests.clear();
        assert_eq!(
            store.stored_fork_admission_result(&row),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    struct MemoryFac1Fixture {
        store: MemoryStore,
        host: pos_crypto::fork_authentication::ForkHostSigningKeyV1,
        adapter: pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1,
        policy: pos_core::fork_authentication::ForkAuthenticationPolicyV1,
        session: ForkAdmissionAuthoritySessionV1,
    }

    fn memory_fac1_fixture() -> Result<MemoryFac1Fixture, Box<dyn std::error::Error>> {
        use pos_core::fork_authentication::{
            ForkAuthenticationAdapterPolicyV1, ForkAuthenticationPolicyV1,
        };
        use pos_crypto::fork_authentication::{
            ForkAuthenticationAdapterSigningKeyV1, ForkHostSigningKeyV1,
        };
        let host = ForkHostSigningKeyV1::from_seed([71; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([72; 32])?;
        let policy = ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "test-adapter".to_owned(),
            verifying_key: adapter.public_key(),
            minimum_assurance: 1,
            registry_bindings: vec![Hash::from_bytes([3; 32])],
        }])?;
        let mut store = MemoryStore::new();
        let key = PublicKey::from_bytes(host.public_key());
        let initialize = store.begin_fork_admission_initialize(key, policy.digest()?)?;
        let signature = host.sign_initialize(&initialize.canonical_bytes())?;
        store.finalize_fork_admission_initialize(&initialize, &signature)?;
        let open = store.begin_fork_admission_open(key, policy.digest()?)?;
        let session =
            store.finalize_fork_admission_open(&open, &host.sign_open(&open.canonical_bytes())?)?;
        Ok(MemoryFac1Fixture {
            store,
            host,
            adapter,
            policy,
            session,
        })
    }

    fn memory_principal_fac1(
        fixture: &MemoryFac1Fixture,
        expires_at: u64,
    ) -> Result<ForkAdmissionHostCommandV1, Box<dyn std::error::Error>> {
        use ciborium::value::Value;
        use pos_core::fork_authentication::{principal_digest_v1, AuthenticatedPrincipalRecordV1};
        let encode = |value: &Value| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut bytes = Vec::new();
            ciborium::into_writer(value, &mut bytes)?;
            Ok(bytes)
        };
        let evidence =
            fixture
                .adapter
                .sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
                    principal: pos_core::PrincipalRefV1::try_new([4; 16], "test.local")?,
                    adapter_id: "test-adapter".to_owned(),
                    assurance: 1,
                    issued_at: 0,
                    expires_at,
                    registry_binding: Hash::from_bytes([3; 32]),
                    operation_nonce: [5; 32],
                })?;
        let verified = pos_crypto::fork_authentication::verify_authenticated_principal_evidence_v1(
            &fixture.policy,
            evidence,
        )?;
        let principal = principal_digest_v1(&verified.evidence().record().principal)?;
        let store_id = fixture.store.fork_admission_host_record()?.store_id();
        let inner = encode(&Value::Array(vec![
            Value::Text("POC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(store_id.as_bytes().to_vec()),
            Value::Bytes(fixture.session.identity().as_bytes().to_vec()),
            Value::Bytes(vec![73; 32]),
            Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
            Value::Bytes(principal.as_bytes().to_vec()),
            Value::Text("owner".to_owned()),
        ]))?;
        let signature = fixture.host.sign_command(&inner, &verified)?;
        let fac1 = encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(inner),
            Value::Bytes(verified.evidence().to_canonical_cbor()?),
            Value::Bytes(signature.as_bytes().to_vec()),
        ]))?;
        Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&fac1)?)
    }

    /// One host-signed FCC1 at cut zero for the fixture's bound Principal.
    fn memory_fork_fac1(
        fixture: &MemoryFac1Fixture,
        operation: u8,
        parent: TimelineId,
    ) -> Result<ForkAdmissionHostCommandV1, Box<dyn std::error::Error>> {
        use ciborium::value::Value;
        use pos_core::fork_authentication::{principal_digest_v1, AuthenticatedPrincipalRecordV1};
        let encode = |value: &Value| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut bytes = Vec::new();
            ciborium::into_writer(value, &mut bytes)?;
            Ok(bytes)
        };
        let evidence =
            fixture
                .adapter
                .sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
                    principal: pos_core::PrincipalRefV1::try_new([4; 16], "test.local")?,
                    adapter_id: "test-adapter".to_owned(),
                    assurance: 1,
                    issued_at: 0,
                    expires_at: u64::MAX,
                    registry_binding: Hash::from_bytes([3; 32]),
                    operation_nonce: [5; 32],
                })?;
        let verified = pos_crypto::fork_authentication::verify_authenticated_principal_evidence_v1(
            &fixture.policy,
            evidence,
        )?;
        let principal = principal_digest_v1(&verified.evidence().record().principal)?;
        let store_id = fixture.store.fork_admission_host_record()?.store_id();
        let inner = encode(&Value::Array(vec![
            Value::Text("FCC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(store_id.as_bytes().to_vec()),
            Value::Bytes(fixture.session.identity().as_bytes().to_vec()),
            Value::Bytes(vec![operation; 32]),
            Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
            Value::Bytes(principal.as_bytes().to_vec()),
            Value::Bytes(parent.inner().to_bytes().to_vec()),
            Value::Integer(0.into()),
            Value::Integer(0.into()),
            Value::Bytes(vec![8; 32]),
            Value::Bytes(vec![9; 32]),
            Value::Integer(1.into()),
            Value::Text(format!("memory-precedence-child-{operation}")),
        ]))?;
        let signature = fixture.host.sign_command(&inner, &verified)?;
        let fac1 = encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(inner),
            Value::Bytes(verified.evidence().to_canonical_cbor()?),
            Value::Bytes(signature.as_bytes().to_vec()),
        ]))?;
        Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&fac1)?)
    }

    /// ADR-106 r3 T10/T14 on `MemoryStore`: committed corruption and a clock
    /// rollback still precede containment of a frozen parent.
    #[test]
    fn fork_admission_memory_corruption_and_clock_rollback_precede_containment(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = memory_fac1_fixture()?;
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        fixture.store.bind_erasure_gate(Arc::clone(&gate))?;
        let principal = memory_principal_fac1(&fixture, u64::MAX)?;
        fixture.store.execute_fork_admission_command(
            &fixture.session,
            &fixture.policy,
            &principal,
        )?;
        let parent = fixture.store.create_timeline("memory-precedence-parent")?;
        let committed = memory_fork_fac1(&fixture, 74, parent.id())?;
        assert!(matches!(
            fixture.store.execute_fork_admission_command(
                &fixture.session,
                &fixture.policy,
                &committed
            ),
            Ok(ForkAdmissionOperationResultV1::Fork(_))
        ));
        gate.freeze_timeline_for_test(parent.id());
        for row in fixture
            .store
            .fork_admission_operations
            .values_mut()
            .filter(|row| row.kind == ForkAdmissionOperationKindV1::Fork)
        {
            row.result_digest = Hash::zero();
        }
        assert_eq!(
            fixture.store.execute_fork_admission_command(
                &fixture.session,
                &fixture.policy,
                &committed
            ),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        fixture
            .store
            .fork_admission_authority
            .last_authority_wall_time = u64::MAX;
        let later = memory_fork_fac1(&fixture, 75, parent.id())?;
        assert_eq!(
            fixture
                .store
                .execute_fork_admission_command(&fixture.session, &fixture.policy, &later),
            Err(pos_core::ForkAdmissionErrorV1::ClockRollback)
        );
        assert_eq!(fixture.store.fork_admission_operations.len(), 2);
        assert_eq!(fixture.store.fork_admissions.len(), 1);
        Ok(())
    }

    #[test]
    fn fork_admission_memory_fac1_rejects_clock_rollback_without_writes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = memory_fac1_fixture()?;
        fixture
            .store
            .fork_admission_authority
            .last_authority_wall_time = u64::MAX;
        let command = memory_principal_fac1(&fixture, u64::MAX)?;
        assert_eq!(
            fixture.store.execute_fork_admission_command(
                &fixture.session,
                &fixture.policy,
                &command
            ),
            Err(pos_core::ForkAdmissionErrorV1::ClockRollback)
        );
        assert!(fixture.store.fork_admission_operations.is_empty());
        assert!(fixture.store.fork_principal_owner_bindings.is_empty());
        assert_eq!(
            fixture
                .store
                .fork_admission_authority
                .last_authority_wall_time,
            u64::MAX
        );
        Ok(())
    }

    #[test]
    fn fork_admission_memory_corrupt_graph_precedes_expired_authentication(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = memory_fac1_fixture()?;
        let command = memory_principal_fac1(&fixture, u64::MAX)?;
        fixture.store.execute_fork_admission_command(
            &fixture.session,
            &fixture.policy,
            &command,
        )?;
        for row in fixture.store.fork_admission_operations.values_mut() {
            row.commitment = Hash::zero();
        }
        let expired = memory_principal_fac1(&fixture, 1)?;
        assert_eq!(
            fixture.store.execute_fork_admission_command(
                &fixture.session,
                &fixture.policy,
                &expired
            ),
            Err(pos_core::ForkAdmissionErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    fn authorized_export_timeline(
        store: &dyn EventStore,
        id: TimelineId,
    ) -> Result<TimelineExport, CoreError> {
        pos_core::store::export_timeline(
            store,
            id,
            crate::TEST_EXPORT_DIGEST,
            &crate::test_export_evaluation(),
        )
    }

    fn authorized_export_timeline_own(
        store: &dyn EventStore,
        id: TimelineId,
    ) -> Result<TimelineExport, CoreError> {
        pos_core::store::export_timeline_own(
            store,
            id,
            crate::TEST_EXPORT_DIGEST,
            &crate::test_export_evaluation(),
        )
    }

    fn authorized_export_timeline_raw(
        store: &dyn EventStore,
        id: TimelineId,
    ) -> Result<TimelineExport, CoreError> {
        pos_core::store::export_timeline_raw(
            store,
            id,
            crate::TEST_EXPORT_DIGEST,
            &crate::test_export_evaluation(),
        )
    }

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected memory-store fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing memory-store fixture value"))
            })
        }
    }

    #[test]
    fn classified_authority_graph_requires_verified_admission_and_every_durable_record() {
        let child_timeline_id = TimelineId::new();
        let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
            operation_id: Hash::from_bytes([1; 32]),
            principal_owner_binding_digest: Hash::from_bytes([2; 32]),
            creator: OwnerIdV1::from_static("test-owner"),
            parent_timeline_id: TimelineId::new(),
            child_timeline_id,
            room_revision_descriptor_hash: Hash::from_bytes([3; 32]),
            parent_logical_head: 0,
            parent_chain_head_hash: Hash::from_bytes([4; 32]),
            completed_fold_cursor: 0,
            post_fold_tick_boundary: 0,
            plugin_composition_hash: Hash::from_bytes([5; 32]),
            attribution_required: false,
            origin: ForkAttributionOriginV1::Local,
        })
        .test_ok();
        let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            registrar_identifier: "test-registrar".to_owned(),
            routes: vec![],
        })
        .test_ok();
        let table = ForkClassifierTableV1::new(ForkClassifierTableInputV1 {
            child_timeline_id,
            fork_admission_digest: admission.digest(),
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            registrar_identifier: source.input().registrar_identifier.clone(),
            source_configuration_revision_digest: source.digest(),
            routes: vec![],
        })
        .test_ok();
        let registration = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
            operation_id: Hash::from_bytes([6; 32]),
            child_timeline_id,
            fork_admission_digest: admission.digest(),
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            classifier_revision_digest: table.digest(),
        })
        .test_ok();
        let operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
            operation_id: Hash::from_bytes([7; 32]),
            child_timeline_id,
            logical_seq: 1,
            event_id: EventId::new(),
            request_digest: Hash::from_bytes([8; 32]),
            source: ForkAppendSourceIdentityV1::HostInternal,
            wall_time: WallTime::from_micros(1),
            payload_hash: Hash::from_bytes([9; 32]),
            classifier_revision_digest: table.digest(),
            fork_admission_digest: admission.digest(),
            event_origin_digest: Hash::from_bytes([10; 32]),
            intervention_admission_digest: None,
        })
        .test_ok();

        let mut store = MemoryStore::new();
        store.fork_admissions.insert(child_timeline_id, admission);
        store.fork_classifier_sources.insert(
            (
                source.input().room_revision_descriptor_hash,
                source.input().registrar_identifier.clone(),
            ),
            source,
        );
        store
            .fork_classifier_tables
            .insert(child_timeline_id, table);
        store
            .fork_classifier_registrations
            .insert(registration.input().operation_id, registration.clone());

        // A canonical FAR1 alone does not establish local append authority.
        // The authenticated POB1/FCC1/child graph must be present as well.
        assert_eq!(
            validate_graph(&store, &operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        store.fork_classifier_registrations.clear();
        assert_eq!(
            validate_graph(&store, &operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        store
            .fork_classifier_registrations
            .insert(registration.input().operation_id, registration);
        store.fork_classifier_sources.clear();
        assert_eq!(
            validate_graph(&store, &operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
    }

    fn validate_graph(
        store: &MemoryStore,
        operation: &ForkAppendOperationV1,
    ) -> Result<(), ForkEventAuthorityErrorV1> {
        store
            .validate_classified_authority_graph(
                operation.input().child_timeline_id,
                operation.input().fork_admission_digest,
                operation.input().classifier_revision_digest,
            )
            .map(|_| ())
    }

    struct ClassifiedAuthorityFixture {
        store: MemoryStore,
        child_timeline_id: TimelineId,
        admission: ForkAdmissionRecordV1,
        table: ForkClassifierTableV1,
        registration: ForkClassifierRegistrationV1,
        operation: ForkAppendOperationV1,
    }

    fn classified_authority_fixture(
    ) -> Result<ClassifiedAuthorityFixture, Box<dyn std::error::Error>> {
        let (mut store, admission_operation) = memory_fork_admission_graph("owner")?;
        let child_timeline_id = admission_operation
            .child_id
            .ok_or_else(|| std::io::Error::other("missing child fixture"))?;
        store.fork_admission_operations.insert(
            (
                ForkAdmissionOperationKindV1::Fork,
                admission_operation.operation_id,
            ),
            admission_operation,
        );
        let admission = store
            .fork_admissions
            .get(&child_timeline_id)
            .cloned()
            .ok_or_else(|| std::io::Error::other("missing admission fixture"))?;
        let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            registrar_identifier: "test-registrar".to_owned(),
            routes: vec![],
        })?;
        let table = ForkClassifierTableV1::new(ForkClassifierTableInputV1 {
            child_timeline_id,
            fork_admission_digest: admission.digest(),
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            registrar_identifier: source.input().registrar_identifier.clone(),
            source_configuration_revision_digest: source.digest(),
            routes: vec![],
        })?;
        let registration = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
            operation_id: Hash::from_bytes([61; 32]),
            child_timeline_id,
            fork_admission_digest: admission.digest(),
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            classifier_revision_digest: table.digest(),
        })?;
        let operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
            operation_id: Hash::from_bytes([62; 32]),
            child_timeline_id,
            logical_seq: 1,
            event_id: EventId::new(),
            request_digest: Hash::from_bytes([63; 32]),
            source: ForkAppendSourceIdentityV1::HostInternal,
            wall_time: WallTime::from_micros(1),
            payload_hash: Hash::from_bytes([64; 32]),
            classifier_revision_digest: table.digest(),
            fork_admission_digest: admission.digest(),
            event_origin_digest: Hash::from_bytes([65; 32]),
            intervention_admission_digest: None,
        })?;
        store.fork_classifier_sources.insert(
            (
                source.input().room_revision_descriptor_hash,
                source.input().registrar_identifier.clone(),
            ),
            source,
        );
        store
            .fork_classifier_tables
            .insert(child_timeline_id, table.clone());
        store
            .fork_classifier_registrations
            .insert(registration.input().operation_id, registration.clone());
        Ok(ClassifiedAuthorityFixture {
            store,
            child_timeline_id,
            admission,
            table,
            registration,
            operation,
        })
    }

    #[test]
    fn classified_authority_graph_accepts_one_verified_registration_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ClassifiedAuthorityFixture {
            mut store,
            registration,
            operation,
            ..
        } = classified_authority_fixture()?;
        assert_eq!(validate_graph(&store, &operation), Ok(()));
        let duplicate = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
            operation_id: Hash::from_bytes([66; 32]),
            ..registration.input().clone()
        })?;
        store
            .fork_classifier_registrations
            .insert(duplicate.input().operation_id, duplicate);
        assert_eq!(
            validate_graph(&store, &operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );

        Ok(())
    }

    #[test]
    fn classified_authority_graph_rejects_each_missing_classifier_record(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = classified_authority_fixture()?;
        let mut missing_table = fixture.store;
        missing_table.fork_classifier_tables.clear();
        assert_eq!(
            validate_graph(&missing_table, &fixture.operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );

        let fixture = classified_authority_fixture()?;
        let mut missing_registration = fixture.store;
        missing_registration.fork_classifier_registrations.clear();
        assert_eq!(
            validate_graph(&missing_registration, &fixture.operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );

        let fixture = classified_authority_fixture()?;
        let mut missing_source = fixture.store;
        missing_source.fork_classifier_sources.clear();
        assert_eq!(
            validate_graph(&missing_source, &fixture.operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    /// A store with one valid classified host Event and its FOP1.
    fn classified_suffix_store(
    ) -> Result<(MemoryStore, TimelineId, ForkAppendOperationV1, Event), Box<dyn std::error::Error>>
    {
        let ClassifiedAuthorityFixture {
            mut store,
            child_timeline_id,
            admission,
            table,
            ..
        } = classified_authority_fixture()?;
        let event = {
            let (timelines, hasher) = (&mut store.timelines, &store.hasher);
            let state = timelines
                .get_mut(&child_timeline_id)
                .ok_or_else(|| std::io::Error::other("missing child state fixture"))?;
            MemoryStore::append_one_to_state(
                state,
                &make_draft(EntityId::new(), b"classified-suffix"),
                hasher.as_ref(),
            )?
        };
        let origin = EventOriginRecordV1::new(EventOriginRecordInputV1 {
            fork_timeline_id: child_timeline_id,
            logical_seq: event.seq.as_u64(),
            event_id: event.id,
            classification: pos_core::ForkEventClassificationV1::new(
                pos_core::ForkEventOriginKindV1::HostInternal,
                false,
            )?,
            classifier_revision_digest: table.digest(),
            fork_admission_digest: admission.digest(),
        })?;
        let suffix_operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
            operation_id: Hash::from_bytes([67; 32]),
            child_timeline_id,
            logical_seq: event.seq.as_u64(),
            event_id: event.id,
            request_digest: Hash::from_bytes([68; 32]),
            source: ForkAppendSourceIdentityV1::HostInternal,
            wall_time: event.wall_time,
            payload_hash: event.payload_hash,
            classifier_revision_digest: table.digest(),
            fork_admission_digest: admission.digest(),
            event_origin_digest: origin.digest(),
            intervention_admission_digest: None,
        })?;
        store.fork_event_origins.insert(event.id, origin);
        store.fork_append_operations.insert(
            suffix_operation.input().operation_id,
            suffix_operation.clone(),
        );
        assert_eq!(store.read_fork_event_suffix(child_timeline_id, 1)?.len(), 1);
        Ok((store, child_timeline_id, suffix_operation, event))
    }

    #[test]
    fn classified_suffix_rejects_missing_and_duplicate_operations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut store, child_timeline_id, suffix_operation, _) = classified_suffix_store()?;
        let missing_event_operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
            operation_id: Hash::from_bytes([69; 32]),
            event_id: EventId::new(),
            ..suffix_operation.input().clone()
        })?;
        store.fork_append_operations.insert(
            missing_event_operation.input().operation_id,
            missing_event_operation.clone(),
        );
        assert_eq!(
            store.read_fork_event_suffix(child_timeline_id, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        store
            .fork_append_operations
            .remove(&missing_event_operation.input().operation_id);

        let duplicate_operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
            operation_id: Hash::from_bytes([70; 32]),
            ..suffix_operation.input().clone()
        })?;
        store.fork_append_operations.insert(
            duplicate_operation.input().operation_id,
            duplicate_operation.clone(),
        );
        assert_eq!(
            store.read_fork_event_suffix(child_timeline_id, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        store
            .fork_append_operations
            .remove(&duplicate_operation.input().operation_id);

        for unbound in [
            ForkAppendOperationInputV1 {
                classifier_revision_digest: Hash::from_bytes([71; 32]),
                ..suffix_operation.input().clone()
            },
            ForkAppendOperationInputV1 {
                fork_admission_digest: Hash::from_bytes([72; 32]),
                ..suffix_operation.input().clone()
            },
        ] {
            store.fork_append_operations.insert(
                suffix_operation.input().operation_id,
                ForkAppendOperationV1::new(unbound)?,
            );
            assert_eq!(
                store.read_fork_event_suffix(child_timeline_id, 1),
                Err(ForkEventAuthorityErrorV1::CorruptAuthority)
            );
        }
        store.fork_append_operations.insert(
            suffix_operation.input().operation_id,
            suffix_operation.clone(),
        );
        assert_eq!(store.read_fork_event_suffix(child_timeline_id, 1)?.len(), 1);
        Ok(())
    }

    /// ADR-105 r6 R6.9: replay and recovery validate the committed Timeline
    /// Event the FOP1 names, and nothing else.
    #[test]
    fn committed_classified_event_requires_the_bound_timeline_event(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut store, child_timeline_id, operation, event) = classified_suffix_store()?;
        assert_eq!(store.committed_classified_event(&operation), Ok(event));
        for input in [
            ForkAppendOperationInputV1 {
                logical_seq: 999,
                ..operation.input().clone()
            },
            ForkAppendOperationInputV1 {
                event_id: EventId::new(),
                ..operation.input().clone()
            },
        ] {
            assert_eq!(
                store.committed_classified_event(&ForkAppendOperationV1::new(input)?),
                Err(ForkEventAuthorityErrorV1::CorruptAuthority)
            );
        }
        store.test_remove_timeline(child_timeline_id);
        assert_eq!(
            store.committed_classified_event(&operation),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    #[test]
    fn classified_suffix_rejects_missing_registration_and_unrecorded_event(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut store, child_timeline_id, suffix_operation, _) = classified_suffix_store()?;
        let registrations = std::mem::take(&mut store.fork_classifier_registrations);
        assert_eq!(
            store.read_fork_event_suffix(child_timeline_id, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        store.fork_classifier_registrations = registrations;
        let stored = store
            .fork_append_operations
            .remove(&suffix_operation.input().operation_id)
            .ok_or_else(|| std::io::Error::other("missing append operation fixture"))?;
        assert_eq!(
            store.read_fork_event_suffix(child_timeline_id, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        store
            .fork_append_operations
            .insert(suffix_operation.input().operation_id, stored);
        assert_eq!(store.read_fork_event_suffix(child_timeline_id, 1)?.len(), 1);
        Ok(())
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful memory-store fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    fn fixture_store(mut store: MemoryStore) -> MemoryStore {
        store
            .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
            .test_ok();
        store
    }

    pub(super) fn new_store() -> MemoryStore {
        fixture_store(MemoryStore::new())
    }

    fn delivery_encode(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).test_ok();
        bytes
    }

    fn delivery_policy(
        adapter: &ForkAuthenticationAdapterSigningKeyV1,
    ) -> ForkAuthenticationPolicyV1 {
        ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "memory-delivery-adapter".to_owned(),
            verifying_key: adapter.public_key(),
            minimum_assurance: 1,
            registry_bindings: vec![Hash::from_bytes([3; 32])],
        }])
        .test_ok()
    }

    fn delivery_session(
        store: &mut MemoryStore,
        host: &ForkHostSigningKeyV1,
        policy: &ForkAuthenticationPolicyV1,
    ) -> ForkAdmissionAuthoritySessionV1 {
        let host_key = PublicKey::from_bytes(host.public_key());
        let initialize = store
            .begin_fork_admission_initialize(host_key, policy.digest().test_ok())
            .test_ok();
        store
            .finalize_fork_admission_initialize(
                &initialize,
                &host
                    .sign_initialize(&initialize.to_canonical_cbor().test_ok())
                    .test_ok(),
            )
            .test_ok();
        let open = store
            .begin_fork_admission_open(host_key, policy.digest().test_ok())
            .test_ok();
        store
            .finalize_fork_admission_open(
                &open,
                &host
                    .sign_open(&open.to_canonical_cbor().test_ok())
                    .test_ok(),
            )
            .test_ok()
    }

    fn delivery_principal_command(
        store: &MemoryStore,
        host: &ForkHostSigningKeyV1,
        adapter: &ForkAuthenticationAdapterSigningKeyV1,
        policy: &ForkAuthenticationPolicyV1,
        session: &ForkAdmissionAuthoritySessionV1,
        operation_id: [u8; 32],
    ) -> ForkAdmissionHostCommandV1 {
        let evidence = adapter
            .sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
                principal: PrincipalRefV1::try_new([4; 16], "memory.test").test_ok(),
                adapter_id: "memory-delivery-adapter".to_owned(),
                assurance: 1,
                issued_at: 0,
                expires_at: u64::MAX,
                registry_binding: Hash::from_bytes([3; 32]),
                operation_nonce: [5; 32],
            })
            .test_ok();
        let verified = verify_authenticated_principal_evidence_v1(policy, evidence).test_ok();
        let principal = principal_digest_v1(&verified.evidence().record().principal).test_ok();
        let inner = delivery_encode(&Value::Array(vec![
            Value::Text("POC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(
                store
                    .fork_admission_host_record()
                    .test_ok()
                    .store_id()
                    .as_bytes()
                    .to_vec(),
            ),
            Value::Bytes(session.identity().as_bytes().to_vec()),
            Value::Bytes(operation_id.to_vec()),
            Value::Bytes(verified.evidence().digest().test_ok().as_bytes().to_vec()),
            Value::Bytes(principal.as_bytes().to_vec()),
            Value::Text("memory-delivery-owner".to_owned()),
        ]));
        let signature = host.sign_command(&inner, &verified).test_ok();
        ForkAdmissionHostCommandV1::from_canonical_cbor(&delivery_encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(inner),
            Value::Bytes(verified.evidence().to_canonical_cbor().test_ok()),
            Value::Bytes(signature.as_bytes().to_vec()),
        ])))
        .test_ok()
    }

    fn delivery_recovery_proof(
        store: &MemoryStore,
        host: &ForkHostSigningKeyV1,
        session: &ForkAdmissionAuthoritySessionV1,
        operation_id: [u8; 32],
    ) -> ForkAdmissionRecoveryProofV1 {
        let recovery = delivery_encode(&Value::Array(vec![
            Value::Text("FRC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(
                store
                    .fork_admission_host_record()
                    .test_ok()
                    .store_id()
                    .as_bytes()
                    .to_vec(),
            ),
            Value::Bytes(session.identity().as_bytes().to_vec()),
            Value::Integer(1.into()),
            Value::Bytes(operation_id.to_vec()),
        ]));
        ForkAdmissionRecoveryProofV1::from_canonical_cbor(&delivery_encode(&Value::Array(vec![
            Value::Text("FRP1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(recovery.clone()),
            Value::Bytes(host.sign_recovery(&recovery).test_ok().as_bytes().to_vec()),
        ])))
        .test_ok()
    }

    fn delivery_owner_claim(
        store: &mut MemoryStore,
        session: &ForkAdmissionAuthoritySessionV1,
        tuple: ForkDeliveryTupleV1,
    ) -> Result<ForkDeliveryClaimV1, String> {
        match store.claim_fork_delivery(session, tuple) {
            Ok(ForkDeliveryClaimOutcomeV1::Owner(claim)) => Ok(claim),
            outcome => Err(format!("expected delivery owner, got {outcome:?}")),
        }
    }

    #[test]
    fn delivery_journal_fails_closed_for_exhausted_or_missing_memory_rows() {
        let host = ForkHostSigningKeyV1::from_seed([201; 32]).test_ok();
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([202; 32]).test_ok();
        let policy = delivery_policy(&adapter);
        let mut store = MemoryStore::new();
        let session = delivery_session(&mut store, &host, &policy);
        let tuple = ForkDeliveryTupleV1::new(
            Hash::from_bytes([203; 32]),
            ForkAdmissionOperationKindV1::PrincipalOwner,
            Hash::from_bytes([204; 32]),
        )
        .test_ok();

        store.fork_delivery_last_fence = u64::MAX;
        assert_eq!(
            store.claim_fork_delivery(&session, tuple),
            Err(ForkDeliveryJournalErrorV1::StorageIndeterminate)
        );

        store.fork_delivery_last_fence = 0;
        let claim = delivery_owner_claim(&mut store, &session, tuple).test_ok();
        let command =
            delivery_principal_command(&store, &host, &adapter, &policy, &session, [204; 32]);
        let proof = delivery_recovery_proof(&store, &host, &session, [204; 32]);
        store.fork_delivery_journal.remove(&tuple.host_request_id);

        assert_eq!(
            store.execute_claimed_fork_delivery(&session, &policy, claim, &command),
            Err(ForkDeliveryJournalErrorV1::Fenced)
        );
        assert_eq!(
            store.mark_fork_delivery_uncertain(&session, claim),
            Err(ForkDeliveryJournalErrorV1::Fenced)
        );
        assert_eq!(
            store.mark_fork_delivery_delivered(&session, claim),
            Err(ForkDeliveryJournalErrorV1::Fenced)
        );
        assert_eq!(
            store.recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([205; 32])),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );
        assert_eq!(
            store.reconcile_fork_delivery_startup(&session, tuple, &proof),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );
    }

    #[test]
    fn delivery_journal_rejects_corrupt_authority_and_orphaned_uncertain_rows() {
        let host = ForkHostSigningKeyV1::from_seed([211; 32]).test_ok();
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([212; 32]).test_ok();
        let policy = delivery_policy(&adapter);
        let mut store = MemoryStore::new();
        let session = delivery_session(&mut store, &host, &policy);
        let tuple = ForkDeliveryTupleV1::new(
            Hash::from_bytes([213; 32]),
            ForkAdmissionOperationKindV1::PrincipalOwner,
            Hash::from_bytes([214; 32]),
        )
        .test_ok();
        let claim = delivery_owner_claim(&mut store, &session, tuple).test_ok();
        let command =
            delivery_principal_command(&store, &host, &adapter, &policy, &session, [214; 32]);
        let proof = delivery_recovery_proof(&store, &host, &session, [214; 32]);

        store.fork_admission_authority.host = None;
        assert_eq!(
            store.execute_claimed_fork_delivery(&session, &policy, claim, &command),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );
        assert_eq!(
            store.recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([215; 32])),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );
        assert_eq!(
            store.reconcile_fork_delivery_startup(&session, tuple, &proof),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );

        let mut store = MemoryStore::new();
        let session = delivery_session(&mut store, &host, &policy);
        let tuple = ForkDeliveryTupleV1::new(
            Hash::from_bytes([216; 32]),
            ForkAdmissionOperationKindV1::PrincipalOwner,
            Hash::from_bytes([217; 32]),
        )
        .test_ok();
        let _claim = delivery_owner_claim(&mut store, &session, tuple).test_ok();
        store
            .fork_delivery_journal
            .get_mut(&tuple.host_request_id)
            .test_ok()
            .state = ForkDeliveryStateV1::Uncertain;
        let proof = delivery_recovery_proof(&store, &host, &session, [217; 32]);
        let wrong_proof = delivery_recovery_proof(&store, &host, &session, [219; 32]);

        assert_eq!(
            store.recover_fork_delivery(&session, tuple, &proof, Hash::zero()),
            Err(ForkDeliveryJournalErrorV1::InvalidTuple)
        );
        assert_eq!(
            store
                .recover_fork_delivery(&session, tuple, &wrong_proof, Hash::from_bytes([218; 32]),),
            Err(ForkDeliveryJournalErrorV1::Conflict)
        );
        assert_eq!(
            store.reconcile_fork_delivery_startup(&session, tuple, &wrong_proof),
            Err(ForkDeliveryJournalErrorV1::Conflict)
        );
        assert_eq!(
            store.recover_fork_delivery(&session, tuple, &proof, Hash::from_bytes([218; 32])),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );
        assert_eq!(
            store.reconcile_fork_delivery_startup(&session, tuple, &proof),
            Err(ForkDeliveryJournalErrorV1::Corrupt)
        );
    }

    #[test]
    fn generic_append_paths_reject_an_admitted_fork_before_mutation() {
        let mut store = new_store();
        let child = store.create_timeline("admitted-child").test_ok();
        store.fork_admissions.insert(
            child.id(),
            ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
                operation_id: Hash::from_bytes([1; 32]),
                principal_owner_binding_digest: Hash::from_bytes([2; 32]),
                creator: OwnerIdV1::from_static("test-owner"),
                parent_timeline_id: TimelineId::new(),
                child_timeline_id: child.id(),
                room_revision_descriptor_hash: Hash::from_bytes([3; 32]),
                parent_logical_head: 0,
                parent_chain_head_hash: Hash::from_bytes([4; 32]),
                completed_fold_cursor: 0,
                post_fold_tick_boundary: 0,
                plugin_composition_hash: Hash::from_bytes([5; 32]),
                attribution_required: false,
                origin: ForkAttributionOriginV1::Local,
            })
            .test_ok(),
        );
        let draft = make_draft(EntityId::new(), b"unclassified");

        assert!(store
            .append_or_duplicate(
                child.id(),
                append_identity(1, 1),
                WallTime::from_micros(1),
                draft.clone(),
            )
            .is_err());
        assert!(store.append_bounded(child.id(), &[draft], 1).is_err());
        assert!(store.append_committed(child.id(), &[]).is_err());
        assert_eq!(store.logical_head(child.id()).test_ok(), Seq::ZERO);
    }

    #[test]
    fn fork_event_suffix_rejects_orphaned_origin_and_intervention_rows() {
        let mut store = new_store();
        let parent = store
            .create_timeline("orphaned-provenance-parent")
            .test_ok();
        let child = store
            .fork(parent.id(), Seq::ZERO, "orphaned-provenance-child")
            .test_ok();
        let event_id = EventId::new();
        let origin = EventOriginRecordV1::new(EventOriginRecordInputV1 {
            fork_timeline_id: child.id(),
            logical_seq: 1,
            event_id,
            classification: pos_core::ForkEventClassificationV1::new(
                ForkEventOriginKindV1::HostInternal,
                false,
            )
            .test_ok(),
            classifier_revision_digest: Hash::from_bytes([1; 32]),
            fork_admission_digest: Hash::from_bytes([2; 32]),
        })
        .test_ok();
        store.fork_event_origins.insert(event_id, origin);
        assert_eq!(
            store.read_fork_event_suffix(child.id(), 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        store.fork_event_origins.clear();
        let intervention = ForkInterventionAdmissionV1::new(ForkInterventionAdmissionInputV1 {
            operation_id: Hash::from_bytes([3; 32]),
            fork_timeline_id: child.id(),
            logical_seq: 1,
            event_id,
            payload_hash: Hash::from_bytes([4; 32]),
            room_revision_descriptor_hash: Hash::from_bytes([5; 32]),
            classifier_revision_digest: Hash::from_bytes([1; 32]),
            fork_admission_digest: Hash::from_bytes([2; 32]),
        })
        .test_ok();
        store
            .fork_intervention_admissions
            .insert(event_id, intervention);
        assert_eq!(
            store.read_fork_event_suffix(child.id(), 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
    }

    #[test]
    fn origin_overflow_rejects_append_without_mutating_memory_state() {
        let mut store = new_store();
        let timeline = store.create_timeline("origin-overflow").test_ok();
        let draft = make_draft(EntityId::new(), b"overflow");
        store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((TimelineId::new(), Seq::from_u64(u64::MAX)));

        let (timelines, hasher) = (&mut store.timelines, &store.hasher);
        let state = timelines.get_mut(&timeline.id()).test_ok();
        assert!(MemoryStore::append_one_to_state(state, &draft, hasher.as_ref()).is_err());
        assert!(store
            .append_or_duplicate_with_limit_visible(
                timeline.id(),
                append_identity(11, 12),
                WallTime::from_micros(1),
                &draft,
                None,
            )
            .is_err());
        let state = store.timelines.get(&timeline.id()).test_ok();
        assert_eq!(state.timeline.head, Seq::ZERO);
        assert!(state.events.is_empty());
        assert!(store.append_identities.is_empty());
    }

    #[test]
    fn origin_overflow_rejects_geographic_admission_without_sidecars() {
        let mut store = new_store();
        let timeline = store.create_timeline("geo-origin-overflow").test_ok();
        let entity = EntityId::new();
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"geo-origin-overflow"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 10),
            ([4; 32], [5; 32]),
        ));
        pair_geographic_enrollment(
            &mut store,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((TimelineId::new(), Seq::from_u64(u64::MAX)));
        assert!(store.admit_geo_location(request).is_err());
        assert!(store.state(timeline.id()).events.is_empty());
        assert!(store.geographic_admission_dedup.is_empty());
        assert!(store.geographic_admission_snapshots.is_empty());
        assert!(store.geographic_admission_links.is_empty());
    }

    #[test]
    fn origin_overflow_rejects_geo_cell_admission_without_sidecars() {
        let mut store = new_store();
        let timeline = store.create_timeline("geo-cell-origin-overflow").test_ok();
        let entity = EntityId::new();
        let draft = geo_cell_draft(
            timeline.id(),
            entity,
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok(),
            12,
            "origin-overflow",
            vec![entity],
            "private",
            9,
            1,
            13,
        );
        let request = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(
                b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01",
            ))
            .test_ok(),
            pos_core::SourceTimeBucket::new(123),
            GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false),
            pos_core::GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                request.fence().draft().consent_record_id().clone(),
                request.fence().draft().consent_revision(),
            ))
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, request.fence().clone())
            .test_ok();
        store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((TimelineId::new(), Seq::from_u64(u64::MAX)));
        assert!(store.admit(request).is_err());
        assert!(store.state(timeline.id()).events.is_empty());
        assert!(store.geographic_cell_dedup.is_empty());
        assert!(store.geographic_cell_snapshots.is_empty());
        assert!(store.geographic_cell_links.is_empty());
    }

    #[test]
    fn default_store_is_fail_closed_in_test_builds_too() {
        let mut store = MemoryStore::new();
        let timeline = store.create_timeline("unbound").test_ok();
        let error = store
            .append(timeline.id(), &[make_draft(EntityId::new(), b"denied")])
            .test_err();
        assert!(matches!(error, CoreError::ErasureContainmentUnavailable));

        let mut unbound = MemoryStore::new().without_erasure_gate();
        let snapshot =
            ErasurePersistenceInventorySnapshotV1::new(Vec::new(), Vec::new(), 1).test_ok();
        let mut query = ErasureVerifiedEmptyInventoryQueryV1::new(snapshot);
        let inventory = query.verified_inventory(1).test_ok();
        let gate = ErasureContainmentGateV1::new_test_open();
        let mut transition = |permit: &ErasureTopologyTransitionPermitV1| {
            assert!(unbound
                .create_timeline_for_host_transition_with_meta(
                    permit,
                    TimelineMeta::root("unbound-transition"),
                )
                .is_err());
            Ok((inventory.clone(), ()))
        };
        gate.install_from_verified_inventory_transition(&mut transition)
            .test_ok();
    }

    fn cover_memory_host_transition_edge_cases(
        store: &mut MemoryStore,
        permit: &ErasureTopologyTransitionPermitV1,
        root: &Timeline,
        child: Timeline,
    ) {
        assert!(store
            .create_timeline_for_host_transition_with_meta(permit, root.meta.clone())
            .is_err());
        assert!(store
            .fork_for_host_transition_with_meta(permit, root.id(), Seq::ZERO, child.meta)
            .is_err());

        let adopted = store
            .create_timeline_for_host_transition_with_meta(
                permit,
                TimelineMeta::root("host-ledger-adopted"),
            )
            .test_ok();
        let (reused_adopted, created) = store
            .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                permit,
                &TimelineMeta::root("host-ledger-adopted"),
                &KeyRegistryStateV1::new(),
            )
            .test_ok();
        assert_eq!(reused_adopted.id(), adopted.id());
        assert!(!created);
    }

    fn cover_memory_host_transition_success(
        store: &mut MemoryStore,
        gate: &ErasureContainmentGateV1,
        inventory: &ErasureVerifiedInventoryV1,
    ) {
        let mut transition = |permit: &ErasureTopologyTransitionPermitV1| {
            let root = store
                .create_timeline_for_host_transition_with_meta(
                    permit,
                    TimelineMeta::root("host-root"),
                )
                .test_ok();
            let meta_root = store
                .create_timeline_for_host_transition_with_meta(
                    permit,
                    TimelineMeta::root("host-root-with-meta"),
                )
                .test_ok();
            assert!(store
                .get_timeline_for_host_transition(permit, root.id())
                .test_ok()
                .is_some());
            assert!(store
                .find_timeline_by_name_for_host_transition(permit, "host-root-with-meta")
                .test_ok()
                .is_some());
            assert!(store
                .find_timeline_by_name_for_host_transition(permit, "missing-host-name")
                .test_ok()
                .is_none());

            let other_parent = store
                .create_timeline_for_host_transition_with_meta(
                    permit,
                    TimelineMeta::root("host-other-parent"),
                )
                .test_ok();
            assert!(store
                .fork_for_host_transition_with_meta(
                    permit,
                    root.id(),
                    Seq::ZERO,
                    TimelineMeta::forked_from(
                        other_parent.id(),
                        Seq::ZERO,
                        "host-child-wrong-parent",
                    ),
                )
                .is_err());
            assert!(store
                .fork_for_host_transition_with_meta(
                    permit,
                    root.id(),
                    Seq::from_u64(1),
                    TimelineMeta::forked_from(root.id(), Seq::ZERO, "host-child-wrong-sequence"),
                )
                .is_err());

            let child_meta = TimelineMeta::forked_from(root.id(), Seq::ZERO, "host-child-meta");
            let child = store
                .fork_for_host_transition_with_meta(permit, root.id(), Seq::ZERO, child_meta)
                .test_ok();
            assert_eq!(child.meta.fork_point, Some((root.id(), Seq::ZERO)));
            let ordinary_child = store
                .fork_for_host_transition_with_meta(
                    permit,
                    root.id(),
                    Seq::ZERO,
                    TimelineMeta::forked_from(root.id(), Seq::ZERO, "host-child"),
                )
                .test_ok();
            assert_eq!(ordinary_child.meta.fork_point, Some((root.id(), Seq::ZERO)));

            cover_memory_host_transition_edge_cases(store, permit, &root, child);

            let ledger_meta = TimelineMeta::root("host-ledger-existing");
            let existing = store
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &ledger_meta,
                    &KeyRegistryStateV1::new(),
                )
                .test_ok();
            assert!(existing.1);
            let reused = store
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &ledger_meta,
                    &KeyRegistryStateV1::new(),
                )
                .test_ok();
            assert!(!reused.1);
            let preallocated = store
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &TimelineMeta::root("host-ledger-with-meta"),
                    &KeyRegistryStateV1::new(),
                )
                .test_ok();
            assert!(preallocated.1);
            assert_ne!(meta_root.id(), preallocated.0.id());
            Ok::<_, ErasureErrorV1>((inventory.clone(), ()))
        };
        gate.install_from_verified_inventory_transition(&mut transition)
            .test_ok();
    }

    fn cover_memory_host_transition_rejections(
        store: &mut MemoryStore,
        inventory: &ErasureVerifiedInventoryV1,
    ) {
        let foreign_gate = ErasureContainmentGateV1::new_test_open();
        let mut rejected = |permit: &ErasureTopologyTransitionPermitV1| {
            assert!(store
                .create_timeline_for_host_transition_with_meta(
                    permit,
                    TimelineMeta::root("foreign-root"),
                )
                .is_err());
            assert!(store
                .create_timeline_for_host_transition_with_meta(
                    permit,
                    TimelineMeta::root("foreign-root-with-meta"),
                )
                .is_err());
            assert!(store
                .fork_for_host_transition_with_meta(
                    permit,
                    TimelineId::new(),
                    Seq::ZERO,
                    TimelineMeta::forked_from(TimelineId::new(), Seq::ZERO, "foreign-child",),
                )
                .is_err());
            assert!(store
                .fork_for_host_transition_with_meta(
                    permit,
                    TimelineId::new(),
                    Seq::ZERO,
                    TimelineMeta::root("foreign-child-with-meta"),
                )
                .is_err());
            assert!(store
                .get_timeline_for_host_transition(permit, TimelineId::new())
                .is_err());
            assert!(store
                .find_timeline_by_name_for_host_transition(permit, "foreign-name")
                .is_err());
            assert!(store
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &TimelineMeta::root("foreign-ledger"),
                    &KeyRegistryStateV1::new(),
                )
                .is_err());
            assert!(store
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &TimelineMeta::root("foreign-ledger-with-meta"),
                    &KeyRegistryStateV1::new(),
                )
                .is_err());
            Ok::<_, ErasureErrorV1>((inventory.clone(), ()))
        };
        foreign_gate
            .install_from_verified_inventory_transition(&mut rejected)
            .test_ok();
    }

    fn cover_memory_mismatched_registry(inventory: &ErasureVerifiedInventoryV1) {
        let mut mismatch = new_store();
        let mut persisted = KeyRegistryStateV1::new();
        persisted
            .register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("host-transition", KeyRoleV1::TimelineIntegritySigning, 1),
                Hash::from_bytes([8; 32]),
                Some(PublicKey::from_bytes([9; 32])),
            ))
            .test_ok();
        mismatch.save_key_registry(&persisted).test_ok();
        let mismatch_gate = Arc::clone(
            mismatch
                .erasure_gate
                .as_ref()
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing mismatch gate"))),
        );
        let mut mismatch_transition = |permit: &ErasureTopologyTransitionPermitV1| {
            assert!(mismatch
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &TimelineMeta::root("mismatched-host-ledger"),
                    &KeyRegistryStateV1::new(),
                )
                .is_err());
            Ok::<_, ErasureErrorV1>((inventory.clone(), ()))
        };
        mismatch_gate
            .install_from_verified_inventory_transition(&mut mismatch_transition)
            .test_ok();
    }

    fn cover_memory_invalid_loaded_registry(inventory: &ErasureVerifiedInventoryV1) {
        let mut invalid_loaded = new_store();
        invalid_loaded.key_registry = Some(super::coverage_entrypoints::invalid_registry());
        let invalid_loaded_gate =
            Arc::clone(invalid_loaded.erasure_gate.as_ref().unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing invalid registry gate"))
            }));
        let mut invalid_loaded_transition = |permit: &ErasureTopologyTransitionPermitV1| {
            assert!(invalid_loaded
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &TimelineMeta::root("invalid-loaded-host-ledger"),
                    &KeyRegistryStateV1::new(),
                )
                .is_err());
            Ok::<_, ErasureErrorV1>((inventory.clone(), ()))
        };
        invalid_loaded_gate
            .install_from_verified_inventory_transition(&mut invalid_loaded_transition)
            .test_ok();
    }

    fn cover_memory_rollback_failure(inventory: &ErasureVerifiedInventoryV1) {
        let mut rollback = new_store();
        let rollback_gate = Arc::clone(
            rollback
                .erasure_gate
                .as_ref()
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing rollback gate"))),
        );
        let mut rollback_transition = |permit: &ErasureTopologyTransitionPermitV1| {
            let error = rollback
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &TimelineMeta::root("rollback-host-ledger-clean"),
                    &super::coverage_entrypoints::invalid_registry(),
                )
                .test_err();
            assert!(matches!(error, CoreError::Serialization(_)));
            assert!(rollback
                .find_timeline_by_name_for_host_transition(permit, "rollback-host-ledger-clean")
                .test_ok()
                .is_none());
            fail_next_visible_delete_for_test();
            let error = rollback
                .initialize_timeline_with_key_registry_for_host_transition_with_meta(
                    permit,
                    &TimelineMeta::root("rollback-host-ledger"),
                    &super::coverage_entrypoints::invalid_registry(),
                )
                .test_err();
            assert!(error.to_string().contains("rollback also failed"));
            Ok::<_, ErasureErrorV1>((inventory.clone(), ()))
        };
        rollback_gate
            .install_from_verified_inventory_transition(&mut rollback_transition)
            .test_ok();
    }

    #[test]
    fn host_transition_store_seams_cover_success_and_rejection_paths() {
        let mut store = new_store();
        let gate =
            Arc::clone(store.erasure_gate.as_ref().unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing memory test gate"))
            }));
        let snapshot =
            ErasurePersistenceInventorySnapshotV1::new(Vec::new(), Vec::new(), 1).test_ok();
        let mut query = ErasureVerifiedEmptyInventoryQueryV1::new(snapshot);
        let inventory = query.verified_inventory(1).test_ok();
        cover_memory_host_transition_success(&mut store, &gate, &inventory);
        cover_memory_host_transition_rejections(&mut store, &inventory);
        let preissued_gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        preissued_gate.issue_topology_store_binding().test_ok();
        assert!(matches!(
            MemoryStore::new().bind_erasure_gate(preissued_gate),
            Err(CoreError::ErasureContainmentUnavailable)
        ));
        cover_memory_mismatched_registry(&inventory);
        cover_memory_invalid_loaded_registry(&inventory);
        cover_memory_rollback_failure(&inventory);
    }

    #[test]
    fn rejoin_adapter_rejects_missing_corrupt_and_remapped_evidence() {
        let proof = crate::test_rejoin_proof();
        let mut store = MemoryStore::new();
        assert_eq!(
            store.store_rejoin_proof(&proof).test_ok(),
            ErasureCasOutcomeV1::Applied
        );
        assert_eq!(
            store.store_rejoin_proof(&proof).test_ok(),
            ErasureCasOutcomeV1::ExactRetry
        );
        let remapped = ErasureReferenceV1::from_digest([9; 32]);
        store
            .erasure_evidence
            .insert(remapped, proof.to_canonical_cbor().test_ok());
        assert_eq!(
            store.load_rejoin_proof(remapped),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        let missing = ErasureReferenceV1::from_digest([10; 32]);
        assert_eq!(store.load_rejoin_proof(missing).test_ok(), None);
        store.erasure_evidence.insert(proof.reference(), vec![0]);
        assert_eq!(
            store.load_rejoin_proof(proof.reference()),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            store.store_rejoin_proof(&proof),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    fn make_draft(entity: EntityId, payload: &[u8]) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new("test.event"),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
    }

    fn geo_cell_consent_record(id: AdmissionSnapshotId, revision: u64) -> AdmissionConsentRecordV1 {
        AdmissionConsentRecordV1::from_persistence_parts(
            id,
            revision,
            CanonicalBytes::from_static(b"\xa1frecordggeo-cell"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn geo_cell_draft(
        timeline: TimelineId,
        entity: EntityId,
        consent_record_id: AdmissionSnapshotId,
        consent_revision: u64,
        purpose: &str,
        entitled_principals: Vec<EntityId>,
        visibility_scope: &str,
        maximum_h3_resolution: u8,
        admission_policy_version: u32,
        admission_epoch: u64,
    ) -> AdmissionEntitlementDraftV1 {
        let record = geo_cell_consent_record(consent_record_id.clone(), consent_revision);
        AdmissionEntitlementDraftV1::new(
            timeline,
            entity,
            consent_record_id,
            consent_revision,
            hash_admission_consent_record_bytes(record.canonical_bytes()),
            purpose,
            entitled_principals,
            visibility_scope,
            maximum_h3_resolution,
            admission_policy_version,
            admission_epoch,
        )
        .test_ok()
    }

    fn pair_geographic_enrollment(
        store: &mut MemoryStore,
        timeline: TimelineId,
        entity: EntityId,
        fence: GeoLocationAdmissionFenceV1,
    ) {
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline, entity, fence, [42; 32],
            ))
            .test_ok();
    }

    struct ErrorClock;

    impl AdmissionClock for ErrorClock {
        fn now(&mut self) -> Result<WallTime, CoreError> {
            Err(CoreError::Storage("clock failed".to_owned()))
        }
    }

    #[test]
    fn lifecycle_clock_errors_and_expiry_overflow_fail_closed() {
        let draft = make_draft(EntityId::new(), b"payload");
        let intent = AppendIntent::new(&draft);
        let mut clock_error = fixture_store(MemoryStore::with_clock(Box::new(ErrorClock)));
        let timeline = clock_error.create_timeline("clock-error").test_ok();
        assert!(clock_error
            .append_intent_or_duplicate(timeline.id(), append_identity(1, 1), intent.clone())
            .is_err());
        assert!(clock_error
            .append_intent_or_duplicate_bounded(
                timeline.id(),
                AppendIdentity::new(
                    AppendDedupKey::from_keyed_hash([3; 32]),
                    AppendDedupScope::from_keyed_hash([4; 32]),
                ),
                intent.clone(),
                1,
            )
            .is_err());
        assert!(clock_error
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .is_err());

        let mut overflow = fixture_store(MemoryStore::with_clock(Box::new(
            pos_core::FixedAdmissionClock(WallTime::from_micros(u64::MAX)),
        )));
        let timeline = overflow.create_timeline("overflow").test_ok();
        assert!(overflow
            .append_intent_or_duplicate(timeline.id(), append_identity(2, 2), intent)
            .is_err());
        drop(timeline);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_clock_and_expiry_failures_leave_no_evidence() {
        let entity = EntityId::new();
        let mut clock_error = fixture_store(MemoryStore::with_clock(Box::new(ErrorClock)));
        let timeline = clock_error.create_timeline("geo-clock-error").test_ok();
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"geo-clock-error"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 10),
            ([4; 32], [5; 32]),
        ));
        pair_geographic_enrollment(
            &mut clock_error,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        assert!(clock_error.admit_geo_location(request).is_err());
        assert!(clock_error.state(timeline.id()).events.is_empty());
        assert!(clock_error.geographic_admission_dedup.is_empty());
        assert!(clock_error.geographic_admission_snapshots.is_empty());
        assert!(clock_error.geographic_admission_links.is_empty());

        let entity = EntityId::new();
        let mut overflow = fixture_store(MemoryStore::with_clock(Box::new(
            pos_core::FixedAdmissionClock(WallTime::from_micros(u64::MAX)),
        )));
        let timeline = overflow.create_timeline("geo-expiry-overflow").test_ok();
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"geo-expiry-overflow"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 10),
            ([4; 32], [5; 32]),
        ));
        pair_geographic_enrollment(
            &mut overflow,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        assert!(overflow.admit_geo_location(request).is_err());
        assert!(overflow.state(timeline.id()).events.is_empty());
        assert!(overflow.geographic_admission_dedup.is_empty());
        assert!(overflow.geographic_admission_snapshots.is_empty());
        assert!(overflow.geographic_admission_links.is_empty());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn geo_cell_duplicate_verifier_rejects_private_corruption() {
        let mut store = new_store();
        let timeline = store
            .create_timeline("geo-cell-private-corruption")
            .test_ok();
        let entity = EntityId::new();
        let cell = ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(
            b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01",
        ))
        .test_ok();
        let draft = geo_cell_draft(
            timeline.id(),
            entity,
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok(),
            12,
            "private-corruption",
            vec![entity],
            "private",
            9,
            1,
            13,
        );
        let request = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            cell,
            pos_core::SourceTimeBucket::new(123),
            GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false),
            pos_core::GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                request.fence().draft().consent_record_id().clone(),
                request.fence().draft().consent_revision(),
            ))
            .test_ok();
        assert!(store
            .set_geo_cell_admission_consent_record(
                AdmissionConsentRecordV1::from_persistence_parts(
                    request.fence().draft().consent_record_id().clone(),
                    0,
                    CanonicalBytes::from_static(b"zero-revision"),
                )
            )
            .is_err());
        assert!(store
            .set_geo_cell_admission_consent_record(
                AdmissionConsentRecordV1::from_persistence_parts(
                    request.fence().draft().consent_record_id().clone(),
                    request.fence().draft().consent_revision(),
                    CanonicalBytes::from_static(b"different-consent"),
                )
            )
            .is_err());
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, request.fence().clone())
            .test_ok();
        let accepted = store.admit(request.clone()).test_ok();
        let event_id = accepted.event_id().test_ok();
        let event_seq = accepted.event_seq().test_ok();
        let snapshot_id = accepted.snapshot_id().test_ok().clone();
        let snapshot_hash = accepted.snapshot_hash().test_ok();
        let fingerprint = request.fingerprint();
        let valid = store.geographic_cell_dedup[&fingerprint].clone();
        assert!(store.verified_geo_cell_duplicate(&valid).is_some());

        let consent_key = (
            request.fence().draft().consent_record_id().clone(),
            request.fence().draft().consent_revision(),
        );
        let consent = store
            .geographic_cell_consent_records
            .remove(&consent_key)
            .test_ok();
        assert!(store.admit(request.clone()).is_err());
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), consent.clone());
        let alternate = AdmissionConsentRecordV1::from_persistence_parts(
            consent_key.0.clone(),
            consent_key.1,
            CanonicalBytes::from_static(b"different-consent"),
        );
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), alternate);
        assert!(store.admit(request.clone()).is_err());
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), consent);

        let dedup_record = store.geographic_cell_dedup.remove(&fingerprint).test_ok();
        let timeline_state = store.timelines.remove(&timeline.id()).test_ok();
        assert!(store.admit(request.clone()).is_err());
        store.timelines.insert(timeline.id(), timeline_state);
        store
            .geographic_cell_dedup
            .insert(fingerprint, dedup_record);

        let draft = geo_cell_draft(
            timeline.id(),
            entity,
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FB0").test_ok(),
            request.fence().draft().consent_revision(),
            "different-intent",
            request.fence().draft().entitled_principals().to_vec(),
            request.fence().draft().visibility_scope(),
            request.fence().draft().maximum_h3_resolution(),
            request.fence().draft().admission_policy_version(),
            request.fence().draft().admission_epoch(),
        );
        let conflict = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            request.cell().clone(),
            request.source_time_bucket(),
            GeoCellAdmissionFenceV1::new(
                draft,
                *request.fence().binding_identity(),
                request.fence().binding_revision(),
                false,
            ),
            pos_core::GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                conflict.fence().draft().consent_record_id().clone(),
                conflict.fence().draft().consent_revision(),
            ))
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, conflict.fence().clone())
            .test_ok();
        assert!(store.admit(conflict).test_ok().is_conflict());
        store
            .geographic_cell_dedup
            .insert(fingerprint, valid.clone());
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                request.fence().draft().consent_record_id().clone(),
                request.fence().draft().consent_revision(),
            ))
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, request.fence().clone())
            .test_ok();

        let timeline_state = store.timelines.remove(&timeline.id()).test_ok();
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .timelines
            .insert(timeline.id(), timeline_state.clone());
        let mut empty_timeline_state = timeline_state.clone();
        empty_timeline_state.events.clear();
        store.timelines.insert(timeline.id(), empty_timeline_state);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store.timelines.insert(timeline.id(), timeline_state);

        let mut bad = valid.clone();
        bad.timeline = TimelineId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.entity = EntityId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.event_id = EventId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.event_seq = Seq::from_u64(event_seq.as_u64() + 1);
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.snapshot_id = AdmissionSnapshotId::new();
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());
        bad = valid.clone();
        bad.snapshot_hash = AdmissionSnapshotHash::from_bytes([0xff; 32]);
        assert!(store.verified_geo_cell_duplicate(&bad).is_none());

        let original_event = store.timelines.get(&timeline.id()).test_ok().events[0].clone();
        let mut corrupt_event = original_event.clone();
        corrupt_event.payload_hash = Hash::zero();
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = corrupt_event;
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        assert!(store.admit(request.clone()).test_ok().is_outcome_unknown());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();
        let mut corrupt_event = original_event.clone();
        corrupt_event.payload = CanonicalBytes::from_static(b"not-a-geo-cell");
        corrupt_event.payload_hash = store.hasher.hash_payload(&corrupt_event.payload);
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = corrupt_event;
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();
        let replacement_id = AdmissionSnapshotId::new();
        let replacement_hash = AdmissionSnapshotHash::from_bytes([31; 32]);
        let replacement_payload = request.payload(replacement_id, replacement_hash).encode();
        let mut corrupt_event = original_event.clone();
        corrupt_event.payload = replacement_payload.clone();
        corrupt_event.payload_hash = store.hasher.hash_payload(&replacement_payload);
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = corrupt_event;
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();

        let snapshot = store
            .geographic_cell_snapshots
            .remove(&snapshot_id)
            .test_ok();
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), snapshot.clone());
        let bad_snapshot = AdmissionEntitlementSnapshotV1::new(
            snapshot_id.clone(),
            &request,
            EventId::new(),
            event_seq,
        );
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), bad_snapshot);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        let bad_snapshot = AdmissionEntitlementSnapshotV1::new(
            snapshot_id.clone(),
            &request,
            event_id,
            event_seq.next(),
        );
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), bad_snapshot);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), snapshot);

        let link = store
            .geographic_cell_links
            .remove(&(timeline.id(), event_id))
            .test_ok();
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), link.clone());
        let mut bad_link = link.clone();
        bad_link.snapshot_id = AdmissionSnapshotId::new();
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        let mut bad_link = link.clone();
        bad_link.snapshot_hash = AdmissionSnapshotHash::from_bytes([0xee; 32]);
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        let mut bad_link = link.clone();
        bad_link.snapshot_cbor = CanonicalBytes::from_static(b"bad-snapshot");
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verified_geo_cell_duplicate(&valid).is_none());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), link);

        let evidence = GeographicReplayEvidenceV1::new(
            timeline.id(),
            event_id,
            event_seq,
            original_event.payload_hash,
            snapshot_id.clone(),
            snapshot_hash,
        );
        assert!(store.verify_geo_cell_event(evidence.clone()).is_ok());

        let consent_key = (
            request.fence().draft().consent_record_id().clone(),
            request.fence().draft().consent_revision(),
        );
        let consent = store
            .geographic_cell_consent_records
            .remove(&consent_key)
            .test_ok();
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_consent_records
            .insert(consent_key.clone(), consent.clone());
        store.geographic_cell_consent_records.insert(
            consent_key.clone(),
            AdmissionConsentRecordV1::from_persistence_parts(
                consent_key.0.clone(),
                consent_key.1,
                CanonicalBytes::from_static(b"different-consent"),
            ),
        );
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_consent_records
            .insert(consent_key, consent);

        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                TimelineId::new(),
                event_id,
                event_seq,
                original_event.payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                EventId::new(),
                event_seq,
                original_event.payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq.next(),
                original_event.payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq,
                Hash::zero(),
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        let original_link = store
            .geographic_cell_links
            .get(&(timeline.id(), event_id))
            .test_ok()
            .clone();
        let mut bad_event = original_event.clone();
        bad_event.event_type = Kind::new("other.event");
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = bad_event;
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event.clone();
        let mut bad_event = original_event.clone();
        bad_event.payload = CanonicalBytes::from_static(b"not-a-geo-cell");
        bad_event.payload_hash = store.hasher.hash_payload(&bad_event.payload);
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = bad_event;
        assert!(store
            .verify_geo_cell_event(GeographicReplayEvidenceV1::new(
                timeline.id(),
                event_id,
                event_seq,
                store.timelines[&timeline.id()].events[0].payload_hash,
                snapshot_id.clone(),
                snapshot_hash,
            ))
            .is_err());
        store.timelines.get_mut(&timeline.id()).test_ok().events[0] = original_event;
        let original_snapshot = store
            .geographic_cell_snapshots
            .get(&snapshot_id)
            .test_ok()
            .clone();
        store.geographic_cell_snapshots.insert(
            snapshot_id.clone(),
            snapshot_id_snapshot(&request, snapshot_id.clone(), EventId::new(), event_seq),
        );
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_snapshots
            .insert(snapshot_id.clone(), original_snapshot);
        let removed_link = store
            .geographic_cell_links
            .remove(&(timeline.id(), event_id))
            .test_ok();
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), removed_link);
        store.geographic_cell_snapshots.remove(&snapshot_id);
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        let previous_snapshot = store.geographic_cell_snapshots.insert(
            snapshot_id.clone(),
            snapshot_id_snapshot(&request, snapshot_id.clone(), event_id, event_seq),
        );
        assert!(previous_snapshot.is_none());
        let mut bad_link = original_link.clone();
        bad_link.snapshot_id = AdmissionSnapshotId::new();
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verify_geo_cell_event(evidence.clone()).is_err());
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), original_link.clone());
        let mut bad_link = original_link;
        bad_link.snapshot_hash = AdmissionSnapshotHash::from_bytes([0xdd; 32]);
        store
            .geographic_cell_links
            .insert((timeline.id(), event_id), bad_link);
        assert!(store.verify_geo_cell_event(evidence).is_err());

        let retained_link = store
            .geographic_cell_links
            .values()
            .next()
            .test_ok()
            .clone();
        store
            .geographic_cell_links
            .insert((TimelineId::new(), event_id), retained_link);
        delete_visible_timeline(&mut store, timeline.id()).test_ok();
    }

    #[test]
    fn geo_cell_expiry_purge_is_atomic_when_later_admission_work_fails() {
        let mut store = new_store();
        let timeline = store
            .create_timeline("geo-cell-expiry-purge-atomicity")
            .test_ok();
        let entity = EntityId::new();
        let draft = geo_cell_draft(
            timeline.id(),
            entity,
            AdmissionSnapshotId::from_canonical("01ARZ3NDEKTSV4RRFFQ69G5FAZ").test_ok(),
            12,
            "expiry-purge",
            vec![entity],
            "private",
            9,
            1,
            13,
        );
        let request = GeoCellAdmissionRequestV1::from_input(GeoCellAdmissionInputV1::new(
            ValidatedGeoCellV1::from_adr031_bytes(&CanonicalBytes::from_static(
                b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01",
            ))
            .test_ok(),
            pos_core::SourceTimeBucket::new(123),
            GeoCellAdmissionFenceV1::new(draft, [7; 32], 11, false),
            pos_core::GeographicAdmissionFingerprintV1::from_ingress([8; 32]),
        ))
        .test_ok();
        store
            .set_geo_cell_admission_consent_record(geo_cell_consent_record(
                request.fence().draft().consent_record_id().clone(),
                request.fence().draft().consent_revision(),
            ))
            .test_ok();
        store
            .set_geo_cell_admission_fence(timeline.id(), entity, request.fence().clone())
            .test_ok();
        assert!(store.admit(request.clone()).test_ok().is_accepted());
        let fingerprint = request.fingerprint();
        store
            .geographic_cell_dedup
            .get_mut(&fingerprint)
            .test_ok()
            .expires_at = WallTime::from_micros(0);
        store.timelines.remove(&timeline.id()).test_ok();

        assert!(store.admit(request).is_err());
        assert!(store.geographic_cell_dedup.contains_key(&fingerprint));
    }

    fn snapshot_id_snapshot(
        request: &GeoCellAdmissionRequestV1,
        snapshot_id: AdmissionSnapshotId,
        event_id: EventId,
        event_seq: Seq,
    ) -> AdmissionEntitlementSnapshotV1 {
        AdmissionEntitlementSnapshotV1::new(snapshot_id, request, event_id, event_seq)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_admission_rejects_unknown_timeline_and_stale_internal_fence() {
        let entity = EntityId::new();
        let missing_timeline = TimelineId::new();
        let fence = GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9));
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            missing_timeline,
            entity,
            CanonicalBytes::from_static(b"geo-stale-timeline"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 9),
            ([4; 32], [5; 32]),
        ));
        let mut store = MemoryStore::default();

        assert!(store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                missing_timeline,
                entity,
                fence,
                [42; 32],
            ))
            .is_err());
        assert!(store.admit_geo_location(request).is_err());
        assert!(store.geographic_admission_dedup.is_empty());
        assert!(store.geographic_admission_snapshots.is_empty());
        assert!(store.geographic_admission_links.is_empty());
    }

    fn assert_missing_geo_fence_is_rejected(store: &mut MemoryStore, timeline: TimelineId) {
        let missing_fence_request =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                timeline,
                EntityId::new(),
                CanonicalBytes::from_static(b"missing-fence"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
                ([4; 32], [5; 32]),
            ));
        let error = store.admit_geo_location(missing_fence_request).test_err();
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&CoreError::GeographicAdmissionValidationFailed)
        );
    }

    #[test]
    fn geographic_admission_keeps_private_sidecars_in_lockstep_with_timeline_lifecycle() {
        let mut store = MemoryStore::default();
        let timeline = store.create_timeline("protected").test_ok();
        let entity = EntityId::new();
        assert_missing_geo_fence_is_rejected(&mut store, timeline.id());
        pair_geographic_enrollment(
            &mut store,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        let request = GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline.id(),
            entity,
            CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
            7,
            ([1; 32], 8, [2; 32]),
            (1, false, 10),
            ([4; 32], [5; 32]),
        ));

        let event_id = store
            .admit_geo_location(request.clone())
            .test_ok()
            .event_id()
            .test_ok();
        let event = &store.state(timeline.id()).events[0];
        let snapshot = store
            .geographic_admission_snapshots
            .get(&event_id)
            .test_ok();
        let link = store
            .geographic_admission_links
            .get(&(timeline.id(), event_id))
            .test_ok();
        assert!(link
            .validate_for(snapshot, timeline.id(), event_id, event.seq)
            .is_ok());
        assert_eq!(store.geographic_admission_dedup.len(), 1);

        assert!(store.admit_geo_location(request).test_ok().is_duplicate());
        assert_eq!(store.geographic_admission_snapshots.len(), 1);
        assert_eq!(store.geographic_admission_links.len(), 1);

        let (retained_timeline, retained_entity) =
            (store.create_timeline("retained").test_ok(), EntityId::new());
        store.revoke_owntracks_enrollment().test_ok();
        pair_geographic_enrollment(
            &mut store,
            retained_timeline.id(),
            retained_entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        let retained_request =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                retained_timeline.id(),
                retained_entity,
                CanonicalBytes::from_static(b"retained-v1-geo-location-payload"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 12),
                ([6; 32], [7; 32]),
            ));
        let retained_event_id = store
            .admit_geo_location(retained_request)
            .test_ok()
            .event_id()
            .test_ok();
        let deleted_event_link = store
            .geographic_admission_links
            .get(&(timeline.id(), event_id))
            .test_ok()
            .clone();
        store
            .geographic_admission_links
            .insert((retained_timeline.id(), event_id), deleted_event_link);
        let retained_event_link = store
            .geographic_admission_links
            .get(&(retained_timeline.id(), retained_event_id))
            .test_ok()
            .clone();
        store
            .geographic_admission_links
            .insert((timeline.id(), retained_event_id), retained_event_link);

        delete_visible_timeline(&mut store, timeline.id()).test_ok();
        assert_eq!(
            store.owntracks_enrollment.status(),
            OwnTracksEnrollmentStatusV1::Active
        );
        assert_eq!(store.geographic_admission_dedup.len(), 1);
        assert_eq!(store.geographic_admission_snapshots.len(), 1);
        assert_eq!(store.geographic_admission_links.len(), 1);
        assert!(store
            .geographic_admission_links
            .contains_key(&(retained_timeline.id(), retained_event_id)));
    }

    struct ReplayFixture {
        store: MemoryStore,
        timeline: TimelineId,
        entity: EntityId,
        event_id: EventId,
        event_seq: Seq,
        event_hash: Hash,
        snapshot_hash: Hash,
    }

    impl ReplayFixture {
        fn evidence(
            &self,
            event_payload_hash: Hash,
            snapshot_hash: Hash,
        ) -> GeoLocationReplayEvidenceV1 {
            GeoLocationReplayEvidenceV1::new(
                self.timeline,
                self.event_id,
                self.event_seq,
                event_payload_hash,
                snapshot_hash,
            )
        }
    }

    fn replay_fixture() -> ReplayFixture {
        let mut store = MemoryStore::default();
        let timeline = store.create_timeline("replay-verifier").test_ok();
        let entity = EntityId::new();
        pair_geographic_enrollment(
            &mut store,
            timeline.id(),
            entity,
            GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
        );
        let accepted = store
            .admit_geo_location(GeoLocationAdmissionRequestV1::from_input(
                GeoLocationAdmissionInputV1::new(
                    timeline.id(),
                    entity,
                    CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                    7,
                    ([1; 32], 8, [2; 32]),
                    (1, false, 10),
                    ([4; 32], [5; 32]),
                ),
            ))
            .test_ok();
        let event_id = accepted.event_id().test_ok();
        let event_seq = accepted.event_seq().test_ok();
        let event_hash = store.state(timeline.id()).events[0].payload_hash;
        let snapshot_hash = store.hasher.hash_payload(
            store
                .geographic_admission_links
                .get(&(timeline.id(), event_id))
                .test_ok()
                .snapshot_cbor(),
        );
        ReplayFixture {
            store,
            timeline: timeline.id(),
            entity,
            event_id,
            event_seq,
            event_hash,
            snapshot_hash,
        }
    }

    fn assert_replay_validation(result: Result<(), CoreError>) {
        assert!(result
            .test_err()
            .to_string()
            .contains("geographic admission validation failed"));
    }

    #[test]
    fn replay_verifier_accepts_only_exact_event_evidence() {
        let mut fixture = replay_fixture();

        assert!(fixture
            .store
            .verify_v1_event_snapshot_link(
                fixture.evidence(fixture.event_hash, fixture.snapshot_hash,)
            )
            .is_ok());
        fixture.store.revoke_owntracks_enrollment().test_ok();
        fixture.store.clock = Box::new(ErrorClock);
        assert!(fixture
            .store
            .verify_v1_event_snapshot_link(
                fixture.evidence(fixture.event_hash, fixture.snapshot_hash)
            )
            .is_ok());
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, Hash::from_bytes([0; 32])),
        ));
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(Hash::from_bytes([0; 32]), fixture.snapshot_hash),
        ));
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            GeoLocationReplayEvidenceV1::new(
                fixture.timeline,
                fixture.event_id,
                fixture.event_seq.next(),
                fixture.event_hash,
                fixture.snapshot_hash,
            ),
        ));
    }

    #[test]
    fn replay_verifier_rejects_changed_canonical_link() {
        let mut fixture = replay_fixture();
        let original_link = fixture
            .store
            .geographic_admission_links
            .get(&(fixture.timeline, fixture.event_id))
            .test_ok()
            .clone();
        let altered_request =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                fixture.timeline,
                fixture.entity,
                CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                8,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
                ([6; 32], [7; 32]),
            ));
        fixture.store.geographic_admission_links.insert(
            (fixture.timeline, fixture.event_id),
            GeoLocationAdmissionLinkV1::for_snapshot(
                fixture.timeline,
                fixture.event_id,
                fixture.event_seq,
                altered_request.snapshot(),
            ),
        );

        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_links
            .insert((fixture.timeline, fixture.event_id), original_link);
    }

    #[test]
    fn replay_verifier_rejects_missing_sidecars_and_non_geographic_event() {
        let mut fixture = replay_fixture();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            GeoLocationReplayEvidenceV1::new(
                fixture.timeline,
                EventId::new(),
                fixture.event_seq,
                fixture.event_hash,
                fixture.snapshot_hash,
            ),
        ));
        let snapshot = fixture
            .store
            .geographic_admission_snapshots
            .remove(&fixture.event_id)
            .test_ok();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_snapshots
            .insert(fixture.event_id, snapshot);
        let mismatched_snapshot =
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                fixture.timeline,
                EntityId::new(),
                CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 9),
                ([6; 32], [7; 32]),
            ))
            .snapshot()
            .clone();
        let original_snapshot = fixture
            .store
            .geographic_admission_snapshots
            .insert(fixture.event_id, mismatched_snapshot)
            .test_ok();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_snapshots
            .insert(fixture.event_id, original_snapshot);
        let link = fixture
            .store
            .geographic_admission_links
            .remove(&(fixture.timeline, fixture.event_id))
            .test_ok();
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            fixture.evidence(fixture.event_hash, fixture.snapshot_hash),
        ));
        fixture
            .store
            .geographic_admission_links
            .insert((fixture.timeline, fixture.event_id), link);
        fixture.store.state_mut(fixture.timeline).test_ok().events[0].event_type =
            Kind::new("test.event");
        assert_replay_validation(fixture.store.verify_v1_event_snapshot_link(
            GeoLocationReplayEvidenceV1::new(
                fixture.timeline,
                fixture.event_id,
                fixture.event_seq,
                fixture.event_hash,
                fixture.snapshot_hash,
            ),
        ));
    }

    fn append_identity(key: u8, scope: u8) -> AppendIdentity {
        AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([scope; 32]),
        )
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_and_get_timeline() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let got = store.get_timeline(tl.id()).test_ok();
        assert_eq!(got.as_ref().map(Timeline::id), Some(tl.id()));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_and_read_events() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts = vec![
            make_draft(entity, b"first"),
            make_draft(entity, b"second"),
            make_draft(entity, b"third"),
        ];
        let committed = store.append(tl.id(), &drafts).test_ok();
        assert_eq!(committed.len(), 3);

        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].payload.as_slice(), b"first");
        assert_eq!(events[1].payload.as_slice(), b"second");
        assert_eq!(events[2].payload.as_slice(), b"third");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_inherited_event_type_before_clone() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let oversized = EventDraft::new(
            EntityId::new(),
            Kind::new("x".repeat(5)),
            CanonicalBytes::from_static(b"x"),
        );
        store.append(root.id(), &[oversized]).test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        let payload_error = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(0, 5, usize::MAX, usize::MAX),
            )
            .test_err();
        assert!(matches!(
            payload_error,
            CoreError::PayloadTooLarge { size: 1 }
        ));
        let error = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 4, usize::MAX, usize::MAX),
            )
            .test_err();

        assert!(matches!(
            error,
            CoreError::EventMetadataTooLarge {
                field: "event_type",
                size: 5
            }
        ));
        let events = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 5, usize::MAX, usize::MAX),
            )
            .test_ok();
        assert_eq!(events.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_aggregate_event_bytes_before_clone() {
        let mut store = new_store();
        let timeline = store.create_timeline("aggregate-bytes").test_ok();
        let entity = EntityId::new();
        store
            .append(
                timeline.id(),
                &[
                    EventDraft::new(entity, Kind::new("x"), CanonicalBytes::from_static(b"1234")),
                    EventDraft::new(entity, Kind::new("x"), CanonicalBytes::from_static(b"5678")),
                ],
            )
            .test_ok();

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes(4, 1, usize::MAX, 2, 9),
            )
            .test_err();
        assert!(matches!(error, CoreError::ReadBytesTooLarge { size: 10 }));

        let events = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes(4, 1, usize::MAX, 2, 10),
            )
            .test_ok();
        assert_eq!(events.len(), 2);

        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 0),
            )
            .test_err();
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_CLONE_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_CLONE_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_PLAN_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_PLAN_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        let child = store
            .fork(timeline.id(), Seq::from_u64(2), "bounded-time-child")
            .test_ok();
        BOUNDED_CHAIN_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_CHAIN_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_EVENT_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_EVENT_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_MATERIALIZE_START_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_MATERIALIZE_START_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));

        BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS.with(|delay| delay.set(20));
        let time_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new_with_total_bytes_and_elapsed(4, 1, usize::MAX, 2, 10, 1_000),
            )
            .test_err();
        BOUNDED_MATERIALIZE_FINAL_DELAY_MILLIS.with(|delay| delay.set(0));
        assert!(matches!(time_error, CoreError::ReadTimeTooLarge { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_enforces_exact_fork_depth_before_chain_growth() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let mut timelines = vec![root];
        for depth in 1..=65 {
            let parent = timelines.last().test_ok();
            let child = store
                .fork(parent.id(), Seq::ZERO, &format!("depth-{depth}"))
                .test_ok();
            timelines.push(child);
        }
        let bounds = EventReadBounds::new(1, 1, 64, usize::MAX);

        assert!(store
            .read_bounded(timelines[64].id(), SeqRange::all(), bounds)
            .test_ok()
            .is_empty());
        let error = store
            .read_bounded(timelines[65].id(), SeqRange::all(), bounds)
            .test_err();
        assert!(matches!(error, CoreError::ForkDepthTooLarge { depth: 65 }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_seeks_late_across_forks_and_fetches_only_the_page() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<_> = (0..4_096).map(|_| make_draft(entity, b"x")).collect();
        store.append(root.id(), &drafts).test_ok();
        let child = store
            .fork(root.id(), Seq::from_u64(4_096), "child")
            .test_ok();
        store
            .append(
                child.id(),
                &[make_draft(entity, b"y"), make_draft(entity, b"z")],
            )
            .test_ok();
        let bounds = EventReadBounds::new(1, usize::MAX, 1, 4);

        BOUNDED_EVENTS_EXAMINED.with(|count| count.set(0));
        let page = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_095)), bounds)
            .test_ok();
        assert_eq!(
            page.iter()
                .map(|event| event.seq.as_u64())
                .collect::<Vec<_>>(),
            vec![4_095, 4_096, 4_097, 4_098]
        );
        BOUNDED_EVENTS_EXAMINED.with(|count| assert_eq!(count.get(), 4));

        BOUNDED_EVENTS_EXAMINED.with(|count| count.set(0));
        let exhausted = store
            .read_bounded(child.id(), SeqRange::from_seq(Seq::from_u64(4_098)), bounds)
            .test_ok();
        assert_eq!(exhausted.len(), 1);
        assert_eq!(exhausted[0].seq.as_u64(), 4_098);
        BOUNDED_EVENTS_EXAMINED.with(|count| assert_eq!(count.get(), 1));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_fails_closed_when_memory_sequence_metadata_is_corrupt() {
        let mut store = new_store();
        let timeline = store.create_timeline("corrupt").test_ok();
        let entity = EntityId::new();
        store
            .append(
                timeline.id(),
                &[make_draft(entity, b"a"), make_draft(entity, b"b")],
            )
            .test_ok();
        store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .events
            .remove(0);

        let error = store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 1),
            )
            .test_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut interior_store = new_store();
        let timeline = interior_store.create_timeline("interior").test_ok();
        interior_store
            .append(
                timeline.id(),
                &[
                    make_draft(entity, b"a"),
                    make_draft(entity, b"b"),
                    make_draft(entity, b"c"),
                ],
            )
            .test_ok();
        interior_store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .events[1]
            .seq = Seq::from_u64(99);
        let error = interior_store
            .read_bounded(
                timeline.id(),
                SeqRange::from_seq(Seq::from_u64(2)),
                EventReadBounds::new(1, usize::MAX, 0, 1),
            )
            .test_err();
        assert!(error.to_string().contains("contiguous Event sequence"));

        let mut fork_store = new_store();
        let root = fork_store.create_timeline("root").test_ok();
        let child = fork_store.fork(root.id(), Seq::ZERO, "child").test_ok();
        fork_store
            .timelines
            .get_mut(&child.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((root.id(), Seq::from_u64(1)));
        let error = fork_store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, usize::MAX, 1, 1),
            )
            .test_err();
        assert!(error.to_string().contains("Fork point exceeds"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_root_count_ignores_many_children_and_caps_at_maximum_plus_one() {
        let mut store = new_store();
        let first = store.create_timeline("first").test_ok();
        for index in 0..256 {
            store
                .fork(first.id(), Seq::ZERO, &format!("child-{index}"))
                .test_ok();
        }
        store.create_timeline("second").test_ok();

        assert_eq!(store.root_timeline_count_bounded(0).test_ok(), 1);
        assert_eq!(store.root_timeline_count_bounded(1).test_ok(), 2);
        assert_eq!(store.root_timeline_count_bounded(10).test_ok(), 2);
        assert_eq!(store.root_timeline_count_bounded(usize::MAX).test_ok(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_is_opaque_and_unchanged() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0x00];
        store.append(tl.id(), &[make_draft(entity, &raw)]).test_ok();
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events[0].payload.as_slice(), &raw[..]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seq_is_monotonically_increasing() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..10).map(|i| make_draft(entity, &[i])).collect();
        let committed = store.append(tl.id(), &drafts).test_ok();
        for (i, e) in committed.iter().enumerate() {
            assert_eq!(e.seq.as_u64(), (i + 1) as u64);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_range_filters_correctly() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).test_ok();

        let events = store
            .read(
                tl.id(),
                SeqRange::bounded(Seq::from_u64(2), Seq::from_u64(4)),
            )
            .test_ok();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].payload.as_slice(), &[1u8]);
        assert_eq!(events[2].payload.as_slice(), &[3u8]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_is_copy_on_write_child_events_do_not_affect_parent() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();

        // Append 3 events to parent
        let parent_drafts = vec![
            make_draft(entity, b"p1"),
            make_draft(entity, b"p2"),
            make_draft(entity, b"p3"),
        ];
        store.append(tl.id(), &parent_drafts).test_ok();

        // Fork at seq 2
        let child = store.fork(tl.id(), Seq::from_u64(2), "child").test_ok();

        // Append to child
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        // Parent still has only 3 events
        let parent_events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(parent_events.len(), 3);

        // Child sees parent[0..2] + its own events = 3 total
        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert_eq!(child_events.len(), 3);
        assert_eq!(child_events[0].payload.as_slice(), b"p1");
        assert_eq!(child_events[1].payload.as_slice(), b"p2");
        assert_eq!(child_events[2].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nested_forks_expose_one_logical_sequence() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[
                    make_draft(entity, b"r1"),
                    make_draft(entity, b"r2"),
                    make_draft(entity, b"r3"),
                ],
            )
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(2), "child").test_ok();
        let child_event = store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(child.head, Seq::ZERO);
        assert_eq!(child_event.seq, Seq::from_u64(3));
        assert_eq!(store.logical_head(child.id()).test_ok(), Seq::from_u64(3));

        let grandchild = store
            .fork(child.id(), Seq::from_u64(3), "grandchild")
            .test_ok();
        let grandchild_event = store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(grandchild_event.seq, Seq::from_u64(4));
        assert_eq!(
            store.logical_head(grandchild.id()).test_ok(),
            Seq::from_u64(4)
        );
        assert_eq!(
            store
                .read(grandchild.id(), SeqRange::all())
                .test_ok()
                .iter()
                .map(|event| (event.seq, event.payload.as_slice()))
                .collect::<Vec<_>>(),
            vec![
                (Seq::from_u64(1), b"r1".as_slice()),
                (Seq::from_u64(2), b"r2".as_slice()),
                (Seq::from_u64(3), b"c1".as_slice()),
                (Seq::from_u64(4), b"g1".as_slice()),
            ]
        );
        assert_eq!(
            store
                .read_event_by_id(grandchild.id(), grandchild_event.id)
                .test_ok()
                .test_ok()
                .seq,
            Seq::from_u64(4)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn logical_sequence_integrity_failures_are_fail_closed() {
        let mut store = new_store();
        let root = store.create_timeline("integrity-root").test_ok();
        let entity = EntityId::new();
        let event = store
            .append(root.id(), &[make_draft(entity, b"root")])
            .test_ok()
            .pop()
            .test_ok();
        assert!(matches!(
            MemoryStore::logical_event(u64::MAX, event),
            Err(CoreError::Storage(_))
        ));
        assert!(matches!(
            store.chain_hash_at(root.id(), Seq::from_u64(2)),
            Err(CoreError::ForkBeyondHead { .. })
        ));

        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        let missing_prefix = ForkChain {
            timelines: vec![root.id(), child.id()],
            fork_seqs: Vec::new(),
        };
        assert!(matches!(
            missing_prefix.segment_prefix(1),
            Err(CoreError::Storage(_))
        ));

        store.timelines.get_mut(&child.id()).test_ok().timeline.head = Seq::from_u64(1);
        let preceding = ForkChain {
            timelines: vec![root.id(), child.id(), TimelineId::new()],
            fork_seqs: vec![Seq::from_u64(1), Seq::ZERO],
        };
        assert!(matches!(
            preceding.segment_length(&store, 1, child.id()),
            Err(CoreError::Storage(_))
        ));
        let exceeding = ForkChain {
            timelines: vec![root.id(), child.id()],
            fork_seqs: vec![Seq::from_u64(2)],
        };
        assert!(matches!(
            exceeding.segment_length(&store, 0, root.id()),
            Err(CoreError::Storage(_))
        ));

        store.timelines.get_mut(&root.id()).test_ok().timeline.head = Seq::from_u64(u64::MAX);
        let child_state = store.timelines.get_mut(&child.id()).test_ok();
        child_state.timeline.meta.fork_point = Some((root.id(), Seq::from_u64(u64::MAX)));
        child_state.timeline.head = Seq::from_u64(1);
        assert!(matches!(
            store.logical_head(child.id()),
            Err(CoreError::Storage(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_segment_integrity_failures_are_fail_closed() {
        let mut store = new_store();
        let root = store.create_timeline("bounded-root").test_ok();
        let child = store.fork(root.id(), Seq::ZERO, "bounded-child").test_ok();
        let chain = vec![root.id(), child.id()];

        store
            .timelines
            .get_mut(&child.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((root.id(), Seq::ZERO));
        assert!(matches!(
            store.bounded_segment_length(&chain, 0, root.id(), 1),
            Err(CoreError::Storage(_))
        ));

        store
            .timelines
            .get_mut(&child.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((root.id(), Seq::from_u64(1)));
        assert!(matches!(
            store.bounded_segment_length(&chain, 0, root.id(), 0),
            Err(CoreError::Storage(_))
        ));

        assert!(store.read_event_by_id(child.id(), EventId::new()).is_err());
        assert!(store.read(child.id(), SeqRange::all()).is_err());
        assert!(store
            .read_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(usize::MAX, usize::MAX, 16, 16),
            )
            .is_err());
        assert!(store.logical_head(child.id()).is_err());
        assert!(store.chain_hash_at(child.id(), Seq::ZERO).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parent_events_after_fork_point_invisible_to_child() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();

        store
            .append(tl.id(), &[make_draft(entity, b"before")])
            .test_ok();
        let child = store.fork(tl.id(), Seq::from_u64(1), "branch").test_ok();

        // Append to parent AFTER fork
        store
            .append(tl.id(), &[make_draft(entity, b"after-fork")])
            .test_ok();

        // Child should NOT see "after-fork"
        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert!(!child_events
            .iter()
            .any(|e| e.payload.as_slice() == b"after-fork"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_beyond_head_returns_error() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let result = store.fork(tl.id(), Seq::from_u64(99), "bad-fork");
        assert!(matches!(result, Err(CoreError::ForkBeyondHead { .. })));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_unknown_timeline_returns_error() {
        let store = new_store();
        let unknown = TimelineId::new();
        let result = store.read(unknown, SeqRange::all());
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_to_unknown_timeline_returns_error() {
        let mut store = new_store();
        let unknown = TimelineId::new();
        let entity = EntityId::new();
        let result = store.append(unknown, &[make_draft(entity, b"x")]);
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_append_is_all_or_nothing_at_the_owned_event_ceiling() {
        let mut store = new_store();
        let timeline = store.create_timeline("bounded").test_ok();
        let entity = EntityId::new();
        let two_drafts = [make_draft(entity, b"one"), make_draft(entity, b"two")];

        assert_eq!(
            store
                .append_bounded(timeline.id(), &two_drafts, 1)
                .test_ok(),
            None
        );
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::ZERO
        );
        assert!(store
            .read_own(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());

        let exact_fit = store
            .append_bounded(timeline.id(), &two_drafts, 2)
            .test_ok()
            .test_ok();
        assert_eq!(exact_fit.len(), 2);
        assert_eq!(exact_fit[0].seq, Seq::from_u64(1));
        assert_eq!(exact_fit[1].seq, Seq::from_u64(2));

        assert_eq!(
            store
                .append_bounded(timeline.id(), &two_drafts, 3)
                .test_ok(),
            None
        );
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::from_u64(2)
        );
        assert_eq!(
            store
                .read_own(timeline.id(), SeqRange::all())
                .test_ok()
                .len(),
            2
        );

        let empty = store
            .append_bounded(timeline.id(), &[], 2)
            .test_ok()
            .test_ok();
        assert!(empty.is_empty());
        assert_eq!(
            store.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::from_u64(2)
        );

        let fork = store
            .fork(timeline.id(), Seq::from_u64(2), "bounded-fork")
            .test_ok();
        let fork_event = store
            .append_bounded(fork.id(), &[make_draft(entity, b"fork")], 1)
            .test_ok()
            .test_ok()
            .pop()
            .test_ok();
        assert_eq!(fork_event.seq, Seq::from_u64(3));
        assert_eq!(
            store
                .append_bounded(fork.id(), &[make_draft(entity, b"too-many")], 1)
                .test_ok(),
            None
        );
        assert_eq!(
            store.read_own(fork.id(), SeqRange::all()).test_ok().len(),
            1
        );

        let overflow_fork = store
            .fork(timeline.id(), Seq::from_u64(2), "overflow-fork")
            .test_ok();
        store
            .timelines
            .get_mut(&overflow_fork.id())
            .test_ok()
            .timeline
            .meta
            .fork_point = Some((timeline.id(), Seq::from_u64(u64::MAX)));
        assert!(matches!(
            store.append_bounded(overflow_fork.id(), &[make_draft(entity, b"overflow")], 1,),
            Err(CoreError::Storage(_))
        ));
        assert_eq!(
            store
                .get_timeline(overflow_fork.id())
                .test_ok()
                .test_ok()
                .head,
            Seq::ZERO
        );
        assert!(store
            .read_own(overflow_fork.id(), SeqRange::all())
            .test_ok()
            .is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_append_rejects_an_owned_head_overflow_before_mutation() {
        let mut store = new_store();
        let timeline = store.create_timeline("overflow-head").test_ok();
        store
            .timelines
            .get_mut(&timeline.id())
            .test_ok()
            .timeline
            .head = Seq::from_u64(u64::MAX);

        assert!(matches!(
            store.append_bounded(
                timeline.id(),
                &[make_draft(EntityId::new(), b"owned-head-overflow")],
                u64::MAX,
            ),
            Err(CoreError::Storage(_))
        ));
        assert!(store
            .read_own(timeline.id(), SeqRange::all())
            .test_ok()
            .is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn list_timelines_returns_all() {
        let mut store = new_store();
        store.create_timeline("a").test_ok();
        store.create_timeline("b").test_ok();
        store.create_timeline("c").test_ok();
        let list = store.list_timelines().test_ok();
        assert_eq!(list.len(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn replay_is_deterministic() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let drafts: Vec<EventDraft> = (0..5u8).map(|i| make_draft(entity, &[i])).collect();
        store.append(tl.id(), &drafts).test_ok();

        let r1 = store.read(tl.id(), SeqRange::all()).test_ok();
        let r2 = store.read(tl.id(), SeqRange::all()).test_ok();
        let ids1: Vec<_> = r1.iter().map(|e| e.id).collect();
        let ids2: Vec<_> = r2.iter().map(|e| e.id).collect();
        assert_eq!(ids1, ids2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_batch_append_returns_empty() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let result = store.append(tl.id(), &[]).test_ok();
        assert!(result.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_at_zero_has_empty_parent_events() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"after")])
            .test_ok();
        let child = store.fork(tl.id(), Seq::ZERO, "empty-fork").test_ok();
        let child_events = store.read(child.id(), SeqRange::all()).test_ok();
        assert!(child_events.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn explicit_wall_time_is_preserved() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let pinned = WallTime::from_micros(123_456_789);
        let draft = make_draft(entity, b"pinned").with_wall_time(pinned);
        let committed = store.append(tl.id(), &[draft]).test_ok();
        assert_eq!(committed[0].wall_time, pinned);
        let read_back = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(read_back[0].wall_time, pinned);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn absent_wall_time_yields_nonzero_timestamp() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        let draft = make_draft(entity, b"no-wall-time");
        // wall_time is None — store must call WallTime::now(), which is >0 on any real system.
        let committed = store.append(tl.id(), &[draft]).test_ok();
        assert!(committed[0].wall_time.as_micros() > 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_store_default_equals_new() {
        // Exercises MemoryStore::default()
        let store: MemoryStore = MemoryStore::default();
        // A fresh default store has no timelines.
        let list = store.list_timelines().test_ok();
        assert!(list.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn grandchild_fork_chain_stitches_correctly() {
        // Exercises compute_chain_hash_at for multi-level fork (parent timeline branch).
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();

        // Append 3 events to root.
        store
            .append(
                root.id(),
                &[
                    make_draft(entity, b"r1"),
                    make_draft(entity, b"r2"),
                    make_draft(entity, b"r3"),
                ],
            )
            .test_ok();

        // Fork root at seq 2 to get child.
        let child = store.fork(root.id(), Seq::from_u64(2), "child").test_ok();

        // Append 2 events to child.
        store
            .append(
                child.id(),
                &[make_draft(entity, b"c1"), make_draft(entity, b"c2")],
            )
            .test_ok();

        // Fork child at logical seq 3 (r1, r2, c1) to get grandchild.
        let grandchild = store
            .fork(child.id(), Seq::from_u64(3), "grandchild")
            .test_ok();

        // Append to grandchild.
        store
            .append(grandchild.id(), &[make_draft(entity, b"g1")])
            .test_ok();

        // Grandchild logical view: r1, r2 (from root up to fork 2),
        // then c1 (from child up to fork 1), then g1.
        let events = store.read(grandchild.id(), SeqRange::all()).test_ok();
        let payloads: Vec<&[u8]> = events.iter().map(|e| e.payload.as_slice()).collect();
        assert_eq!(payloads, vec![b"r1" as &[u8], b"r2", b"c1", b"g1"]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_unknown_parent_returns_timeline_not_found() {
        let mut store = new_store();
        let unknown = TimelineId::new();
        let result = store.fork(unknown, Seq::ZERO, "orphan");
        assert!(matches!(result, Err(CoreError::TimelineNotFound(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_fails_when_fork_parent_metadata_removed() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"evt")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        store.test_remove_timeline(root.id());
        let err = store.read(child.id(), SeqRange::all()).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_fails_when_ancestor_metadata_removed() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"evt")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        store.test_remove_timeline(root.id());
        let err = store.fork(child.id(), Seq::ZERO, "grandchild").test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_rejects_cyclic_fork_ancestry() {
        let mut store = new_store();
        let timeline = store.create_timeline("cycle").test_ok();
        store.test_corrupt(TestCorruption::ForkParent {
            timeline: timeline.id(),
            parent: timeline.id(),
            fork_seq: Seq::ZERO,
        });

        let error = store.read(timeline.id(), SeqRange::all()).test_err();
        assert!(error.to_string().contains("fork ancestry contains a cycle"));
        let bounded_error = store
            .read_bounded(
                timeline.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .test_err();
        assert!(bounded_error
            .to_string()
            .contains("fork ancestry contains a cycle"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_corruption_rejects_a_missing_timeline_target() {
        let mut store = new_store();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.test_corrupt(TestCorruption::ForkParent {
                timeline: TimelineId::new(),
                parent: TimelineId::new(),
                fork_seq: Seq::ZERO,
            });
        }));
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_read_rejects_unknown_timeline() {
        let store = new_store();
        let bounded_error = store
            .read_bounded(
                TimelineId::new(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .test_err();
        assert!(bounded_error.to_string().contains("timeline not found"));
    }

    #[test]
    fn bounded_chain_rejects_a_missing_ancestor() {
        let mut store = new_store();
        let parent = store.create_timeline("parent").test_ok();
        let child = store.fork(parent.id(), Seq::ZERO, "child").test_ok();
        store.test_remove_timeline(parent.id());

        let error = store
            .collect_events_in_range_bounded(
                child.id(),
                SeqRange::all(),
                EventReadBounds::new(1, 1, 1, 1),
            )
            .test_err();
        assert!(error
            .to_string()
            .contains(&format!("timeline not found: {}", parent.id())));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn multiple_forks_from_same_parent_are_independent() {
        let mut store = new_store();
        let tl = store.create_timeline("main").test_ok();
        let entity = EntityId::new();
        store
            .append(tl.id(), &[make_draft(entity, b"shared")])
            .test_ok();

        let branch_a = store.fork(tl.id(), Seq::from_u64(1), "a").test_ok();
        let branch_b = store.fork(tl.id(), Seq::from_u64(1), "b").test_ok();

        store
            .append(branch_a.id(), &[make_draft(entity, b"a-only")])
            .test_ok();
        store
            .append(branch_b.id(), &[make_draft(entity, b"b-only")])
            .test_ok();

        let a_events = store.read(branch_a.id(), SeqRange::all()).test_ok();
        let b_events = store.read(branch_b.id(), SeqRange::all()).test_ok();

        assert!(a_events.iter().any(|e| e.payload.as_slice() == b"a-only"));
        assert!(!a_events.iter().any(|e| e.payload.as_slice() == b"b-only"));
        assert!(b_events.iter().any(|e| e.payload.as_slice() == b"b-only"));
        assert!(!b_events.iter().any(|e| e.payload.as_slice() == b"a-only"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_preserves_timeline_and_event_ids() {
        use pos_core::store::import_timeline_with_id;

        let mut src = new_store();
        let tl = src.create_timeline("shared").test_ok();
        let entity = EntityId::new();
        let committed = src
            .append(
                tl.id(),
                &[make_draft(entity, b"one"), make_draft(entity, b"two")],
            )
            .test_ok();
        let export = authorized_export_timeline(&src, tl.id()).test_ok();
        let original_tl_id = tl.id();
        let original_event_ids: Vec<_> = committed.iter().map(|e| e.id).collect();

        let mut dst = new_store();
        let imported = import_timeline_with_id(&mut dst, export).test_ok();
        assert_eq!(imported.id(), original_tl_id);
        let events = dst.read(original_tl_id, SeqRange::all()).test_ok();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, original_event_ids[0]);
        assert_eq!(events[1].id, original_event_ids[1]);
        assert_eq!(events[0].payload.as_slice(), b"one");
        assert_eq!(events[1].payload.as_slice(), b"two");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_rejects_duplicate_and_missing_parent() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let err = store.create_timeline_with_meta(root.meta).test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        let orphan = TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "orphan");
        let err = store.create_timeline_with_meta(orphan).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_fork_uses_parent_chain() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .test_ok();
        let child_meta = TimelineMeta {
            id: TimelineId::new(),
            mode: pos_core::timeline::TimelineMode::Historical,
            name: Some("child".to_owned()),
            owner: None,
            fork_point: Some((root.id(), Seq::from_u64(1))),
        };
        let child = store.create_timeline_with_meta(child_meta).test_ok();
        assert!(child.meta.fork_point.is_some());
        store.append_committed(child.id(), &[]).test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_is_atomic_on_mid_batch_failure() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let good = store
            .append(tl.id(), &[make_draft(entity, b"ok")])
            .test_ok()
            .remove(0);

        let mut bad = good.clone();
        bad.id = EventId::new();
        bad.seq = Seq::from_u64(2);
        bad.payload = CanonicalBytes::from_vec(b"bad".to_vec());
        bad.payload_hash = pos_core::Hash::from_bytes([9u8; 32]); // mismatch

        let mut later = good;
        later.id = EventId::new();
        later.seq = Seq::from_u64(3);
        later.payload = CanonicalBytes::from_vec(b"later".to_vec());
        later.payload_hash = pos_crypto::chain::hash_payload(&later.payload);

        let err = store.append_committed(tl.id(), &[bad, later]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // No partial apply: still only the originally appended event.
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"ok");
        assert_eq!(
            store.get_timeline(tl.id()).test_ok().test_ok().head,
            Seq::from_u64(1)
        );
    }

    #[test]
    fn delete_timeline_removes_events_and_blocks_with_forks() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"r1")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();

        let err = store.delete_timeline(root.id()).test_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&CoreError::Storage(String::new()))
        );

        store.delete_timeline(child.id()).test_ok();
        store.delete_timeline(root.id()).test_ok();
        assert_eq!(store.get_timeline(root.id()).test_ok(), None);
        let err = store.delete_timeline(root.id()).test_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&CoreError::TimelineNotFound(TimelineId::new()))
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_timeline_with_id_rolls_back_create_on_append_fail() {
        use pos_core::store::import_timeline_with_id;

        let mut src = new_store();
        let tl = src.create_timeline("shared").test_ok();
        let entity = EntityId::new();
        let mut committed = src.append(tl.id(), &[make_draft(entity, b"one")]).test_ok();
        let export = authorized_export_timeline(&src, tl.id()).test_ok();
        // Corrupt payload hash so append_committed fails after create.
        let mut bad_export = export;
        bad_export.events[0].payload_hash = pos_core::Hash::from_bytes([1u8; 32]);

        let mut dst = new_store();
        let err = import_timeline_with_id(&mut dst, bad_export).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
        assert!(dst.get_timeline(tl.id()).test_ok().is_none());
        let _ = committed.remove(0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_validates_seq_and_payload_hash() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let mut good = store
            .append(tl.id(), &[make_draft(entity, b"x")])
            .test_ok()
            .remove(0);

        // Empty committed append is ok.
        store.append_committed(tl.id(), &[]).test_ok();

        // Collision with existing head (not contiguous — expects head+1).
        let err = store.append_committed(tl.id(), &[good.clone()]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Missing timeline.
        let err = store
            .append_committed(TimelineId::new(), &[good.clone()])
            .test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));

        // Bad payload hash.
        good.seq = Seq::from_u64(2);
        good.payload_hash = pos_core::Hash::from_bytes([9u8; 32]);
        let err = store.append_committed(tl.id(), &[good.clone()]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));

        // Seq gap rejected.
        good.seq = Seq::from_u64(3);
        good.payload_hash = pos_crypto::chain::hash_payload(&good.payload);
        let err = store.append_committed(tl.id(), &[good.clone()]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("contiguous")));

        // Seq 0 rejected.
        good.seq = Seq::ZERO;
        let err = store.append_committed(tl.id(), &[good]).test_err();
        assert!(matches!(err, CoreError::Storage(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_duplicate_event_id() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let first = store
            .append(tl.id(), &[make_draft(entity, b"a")])
            .test_ok()
            .remove(0);

        let mut dup = first;
        dup.seq = Seq::from_u64(2);
        dup.payload = CanonicalBytes::from_vec(b"b".to_vec());
        dup.payload_hash = pos_crypto::chain::hash_payload(&dup.payload);
        // same EventId as first
        let err = store.append_committed(tl.id(), &[dup]).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_committed_rejects_duplicate_id_in_batch() {
        let mut store = new_store();
        let tl = store.create_timeline("t").test_ok();
        let entity = EntityId::new();
        let id = EventId::new();
        let mk = |seq: u64, payload: &[u8]| {
            let payload = CanonicalBytes::from_vec(payload.to_vec());
            Event {
                id,
                entity,
                event_type: Kind::new("t"),
                payload: payload.clone(),
                wall_time: WallTime::now(),
                seq: Seq::from_u64(seq),
                causation_id: None,
                correlation_id: None,
                schema_version: pos_core::SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                origin: None,
                payload_hash: pos_crypto::chain::hash_payload(&payload),
            }
        };
        let err = store
            .append_committed(tl.id(), &[mk(1, b"a"), mk(2, b"b")])
            .test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("duplicate")));
    }

    #[test]
    fn generic_committed_geographic_events_are_rejected() {
        let mut store = new_store();
        let timeline = store.create_timeline("geo").test_ok();
        let payload = CanonicalBytes::from_vec(b"protected".to_vec());
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("geo.location"),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        assert!(store.append_committed(timeline.id(), &[event]).is_err());
        assert!(store
            .append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("ordinary.event"),
                    CanonicalBytes::from_vec(b"allowed".to_vec()),
                )],
            )
            .is_ok());
        assert_eq!(
            store.read(timeline.id(), SeqRange::all()).test_ok().len(),
            1
        );
    }

    #[test]
    fn read_event_by_id_fails_closed_for_unknown_timeline() {
        let store = new_store();
        assert!(store
            .read_event_by_id(TimelineId::new(), EventId::new())
            .test_err()
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn read_own_helper_returns_matching_event() {
        let mut store = new_store();
        let timeline = store.create_timeline("read-own-helper").test_ok();
        store
            .append(
                timeline.id(),
                &[
                    make_draft(EntityId::new(), b"matching-event"),
                    make_draft(EntityId::new(), b"excluded-event"),
                ],
            )
            .test_ok();

        let events = read_own(
            &store,
            timeline.id(),
            SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1)),
        )
        .test_ok();
        assert_eq!(events.len(), 1);

        let all_events = read_own(&store, timeline.id(), SeqRange::all()).test_ok();
        assert_eq!(all_events.len(), 2);
    }

    #[test]
    fn child_reads_do_not_include_parent_events_after_a_fork_point() {
        let mut store = new_store();
        let parent = store.create_timeline("lookup-parent").test_ok();
        store
            .append(parent.id(), &[make_draft(EntityId::new(), b"before-fork")])
            .test_ok();
        let child = store
            .fork(parent.id(), Seq::from_u64(1), "lookup-child")
            .test_ok();
        store
            .append(parent.id(), &[make_draft(EntityId::new(), b"after-fork")])
            .test_ok();

        assert_eq!(store.read(child.id(), SeqRange::all()).test_ok().len(), 1);
    }

    #[test]
    fn delete_timeline_helper_removes_append_identity() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-helper").test_ok();
        let intent = AppendIntent::new(&make_draft(EntityId::new(), b"identified-event"));
        store
            .append_intent_or_duplicate(timeline.id(), append_identity(17, 17), intent)
            .test_ok();

        let retained_timeline = store.create_timeline("retained-identity").test_ok();
        let retained = AppendIntent::new(&make_draft(EntityId::new(), b"retained-event"));
        store
            .append_intent_or_duplicate(retained_timeline.id(), append_identity(18, 18), retained)
            .test_ok();

        store
            .fork(retained_timeline.id(), Seq::ZERO, "retained-child")
            .test_ok();

        delete_timeline(&mut store, timeline.id()).test_ok();
        assert_eq!(store.append_identities.len(), 1);
    }

    #[test]
    fn delete_timeline_helper_handles_an_empty_identity_map() {
        let mut store = new_store();
        let timeline = store.create_timeline("delete-empty-identities").test_ok();

        delete_timeline(&mut store, timeline.id()).test_ok();

        assert!(store.append_identities.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mutable_state_lookup_rejects_an_unknown_timeline() {
        let mut store = new_store();
        assert!(mutable_state(&mut store.timelines, TimelineId::new()).is_err());
        assert!(store.state_mut(TimelineId::new()).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_own_fork_roundtrip_preserves_cow() {
        use pos_core::store::import_timeline_with_id;

        let mut src = new_store();
        let root = src.create_timeline("root").test_ok();
        let entity = EntityId::new();
        src.append(
            root.id(),
            &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
        )
        .test_ok();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        // Logical export flattens fork meta.
        let logical = authorized_export_timeline(&src, child.id()).test_ok();
        assert!(logical.timeline.meta.fork_point.is_none());
        assert_eq!(logical.events.len(), 2); // parent[..1] + child

        // Own export keeps CoW shape (`_raw` is a legacy alias of `_own`).
        let own = authorized_export_timeline_own(&src, child.id()).test_ok();
        let raw_alias = authorized_export_timeline_raw(&src, child.id()).test_ok();
        assert_eq!(own.timeline.id(), raw_alias.timeline.id());
        assert_eq!(own.events.len(), raw_alias.events.len());
        assert_eq!(own.parent_fork_hash, raw_alias.parent_fork_hash);
        assert_eq!(
            own.timeline.meta.fork_point,
            Some((root.id(), Seq::from_u64(1)))
        );
        assert_eq!(own.events.len(), 1);
        assert_eq!(own.events[0].payload.as_slice(), b"c1");

        let mut dst = new_store();
        let parent_export = authorized_export_timeline_own(&src, root.id()).test_ok();
        import_timeline_with_id(&mut dst, parent_export).test_ok();
        let imported = import_timeline_with_id(&mut dst, own).test_ok();
        assert_eq!(imported.id(), child.id());
        assert!(imported.meta.fork_point.is_some());
        let stitched = dst.read(child.id(), SeqRange::all()).test_ok();
        assert_eq!(stitched.len(), 2);
        assert_eq!(stitched[0].payload.as_slice(), b"p1");
        assert_eq!(stitched[1].payload.as_slice(), b"c1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_own_skips_parent_events() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        store
            .append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();
        let own = store.read_own(child.id(), SeqRange::all()).test_ok();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].payload.as_slice(), b"c1");
        let missing = store
            .read_own(TimelineId::new(), SeqRange::all())
            .test_err();
        assert!(matches!(missing, CoreError::TimelineNotFound(_)));

        let bounded = store
            .read_own(
                child.id(),
                SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(1)),
            )
            .test_ok();
        assert_eq!(bounded.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_rejects_fork_beyond_head() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let mut meta = TimelineMeta::forked_from(root.id(), Seq::from_u64(9), "bad");
        meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(meta).test_err();
        assert!(matches!(err, CoreError::ForkBeyondHead { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nested_fork_chain_hash_ignores_parent_events_after_fork() {
        let mut store = new_store();
        let root = store.create_timeline("root").test_ok();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[make_draft(entity, b"r1"), make_draft(entity, b"r2")],
            )
            .test_ok();
        let mid = store.fork(root.id(), Seq::from_u64(1), "mid").test_ok();
        store
            .append(mid.id(), &[make_draft(entity, b"m1")])
            .test_ok();
        // Parent continues after fork — must not affect mid/leaf chain heads.
        store
            .append(root.id(), &[make_draft(entity, b"r3")])
            .test_ok();

        let mut leaf_meta = TimelineMeta::forked_from(mid.id(), Seq::from_u64(2), "leaf");
        leaf_meta.id = TimelineId::new();
        let leaf = store.create_timeline_with_meta(leaf_meta).test_ok();

        // Import-equivalent append on leaf must hash from the CoW snapshot, not root's new tip.
        let payload = CanonicalBytes::from_vec(b"l1".to_vec());
        let ev = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: payload.clone(),
            wall_time: WallTime::now(),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        store.append_committed(leaf.id(), &[ev]).test_ok();
        let stitched = store.read(leaf.id(), SeqRange::all()).test_ok();
        // leaf @ logical mid:2 → r1 + m1 + leaf l1; root's post-fork r3 stays invisible.
        assert_eq!(stitched.len(), 3);
        assert_eq!(stitched[0].payload.as_slice(), b"r1");
        assert_eq!(stitched[1].payload.as_slice(), b"m1");
        assert_eq!(stitched[2].payload.as_slice(), b"l1");
        assert!(stitched.iter().all(|e| e.payload.as_slice() != b"r3"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn logical_fork_export_remints_ids_so_import_beside_parent_works() {
        use pos_core::store::import_timeline_with_id;

        let mut src = new_store();
        let root = src.create_timeline("root").test_ok();
        let entity = EntityId::new();
        src.append(
            root.id(),
            &[make_draft(entity, b"p1"), make_draft(entity, b"p2")],
        )
        .test_ok();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        src.append(child.id(), &[make_draft(entity, b"c1")])
            .test_ok();

        let logical = authorized_export_timeline(&src, child.id()).test_ok();
        assert!(logical.timeline.meta.fork_point.is_none());
        assert_eq!(logical.timeline.head, Seq::from_u64(2));
        let parent_ids: std::collections::HashSet<_> = src
            .read_own(root.id(), SeqRange::all())
            .test_ok()
            .into_iter()
            .map(|e| e.id)
            .collect();
        for e in &logical.events {
            assert!(!parent_ids.contains(&e.id));
        }

        let mut dst = new_store();
        import_timeline_with_id(
            &mut dst,
            authorized_export_timeline(&src, root.id()).test_ok(),
        )
        .test_ok();
        // Flattened child import must not collide with parent EventIds.
        import_timeline_with_id(&mut dst, logical).test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_timeline_with_meta_surfaces_broken_parent_chain() {
        let mut store = new_store();
        // Parent row exists but its fork_point points at a missing grandparent.
        let mut broken_meta =
            TimelineMeta::forked_from(TimelineId::new(), Seq::from_u64(1), "broken");
        broken_meta.id = TimelineId::new();
        let broken = Timeline::new(broken_meta);
        store.timelines.insert(
            broken.id(),
            TimelineState::new(broken.clone(), pos_crypto::chain::genesis_hash()),
        );

        let mut child_meta = TimelineMeta::forked_from(broken.id(), Seq::ZERO, "child");
        child_meta.id = TimelineId::new();
        let err = store.create_timeline_with_meta(child_meta).test_err();
        assert!(matches!(err, CoreError::TimelineNotFound(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_rejects_fork_parent_chain_hash_mismatch() {
        use pos_core::store::import_timeline_with_id;

        let mut src = new_store();
        let root = src.create_timeline("root").test_ok();
        let entity = EntityId::new();
        src.append(root.id(), &[make_draft(entity, b"p1")])
            .test_ok();
        let child = src.fork(root.id(), Seq::from_u64(1), "child").test_ok();

        let mut dst = new_store();
        // Divergent parent with same id but different payload.
        let mut parent_export = authorized_export_timeline_own(&src, root.id()).test_ok();
        parent_export.events[0].payload = CanonicalBytes::from_vec(b"OTHER".to_vec());
        parent_export.events[0].payload_hash =
            pos_crypto::chain::hash_payload(&parent_export.events[0].payload);
        import_timeline_with_id(&mut dst, parent_export).test_ok();

        let child_export = authorized_export_timeline_own(&src, child.id()).test_ok();
        assert!(child_export.parent_fork_hash.is_some());
        let err = import_timeline_with_id(&mut dst, child_export).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("chain hash mismatch")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_rejects_when_chain_hash_at_fails() {
        use pos_core::store::import_timeline_with_id;

        struct HashFailOnImport {
            base: MemoryStore,
        }
        impl EventStore for HashFailOnImport {
            fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
                self.base.create_timeline(name)
            }
            fn append(
                &mut self,
                timeline: TimelineId,
                drafts: &[EventDraft],
            ) -> Result<Vec<Event>, CoreError> {
                self.base.append(timeline, drafts)
            }
            fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
                self.base.read(timeline, range)
            }
            fn read_own(
                &self,
                timeline: TimelineId,
                range: SeqRange,
            ) -> Result<Vec<Event>, CoreError> {
                self.base.read_own(timeline, range)
            }
            fn fork(
                &mut self,
                parent: TimelineId,
                at_seq: Seq,
                name: &str,
            ) -> Result<Timeline, CoreError> {
                self.base.fork(parent, at_seq, name)
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                self.base.list_timelines()
            }
            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                self.base.get_timeline(id)
            }
            fn create_timeline_with_meta(
                &mut self,
                meta: TimelineMeta,
            ) -> Result<Timeline, CoreError> {
                self.base.create_timeline_with_meta(meta)
            }
            fn append_committed(
                &mut self,
                timeline: TimelineId,
                events: &[Event],
            ) -> Result<(), CoreError> {
                self.base.append_committed(timeline, events)
            }
            fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
                self.base.delete_timeline(id)
            }
            fn chain_hash_at(&self, _: TimelineId, _: Seq) -> Result<Hash, CoreError> {
                Err(CoreError::Storage("chain lookup failed".to_owned()))
            }
            fn import_committed(
                &mut self,
                meta: TimelineMeta,
                events: &[Event],
            ) -> Result<Timeline, CoreError> {
                pos_core::store::import_committed_with_rollback(self, meta, events)
            }
        }

        let mut store = HashFailOnImport { base: new_store() };
        let parent = store.create_timeline("root").test_ok();
        let mut meta = TimelineMeta::forked_from(parent.id(), Seq::ZERO, "child");
        meta.id = TimelineId::new();
        let export = TimelineExport {
            timeline: Timeline::new(meta),
            events: vec![],
            parent_fork_hash: Some(Hash::zero()),
        };
        let err = import_timeline_with_id(&mut store, export).test_err();
        assert!(matches!(err, CoreError::Storage(ref m) if m.contains("chain lookup")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn with_hasher_uses_custom_hasher() {
        let mut store = fixture_store(MemoryStore::with_hasher(Box::new(
            pos_crypto::chain::Blake3Hasher,
        )));
        let tl = store.create_timeline("hasher-test").test_ok();
        let entity = EntityId::new();
        let drafts = [make_draft(entity, b"payload")];
        let events = store.append(tl.id(), &drafts).test_ok();
        assert_eq!(events.len(), 1);
        assert!(!events[0].payload_hash.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn key_registry_snapshot_and_authorized_append_reject_stale_state() {
        let mut store = new_store();
        assert_eq!(store.load_key_registry().test_ok(), None);
        let mut persisted = KeyRegistryStateV1::new();
        persisted
            .register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
                Hash::from_bytes([3; 32]),
                Some(PublicKey::from_bytes([4; 32])),
            ))
            .test_ok();
        store.save_key_registry(&persisted).test_ok();
        assert_eq!(store.load_key_registry().test_ok(), Some(persisted.clone()));

        let timeline = store.create_timeline("stale-registry").test_ok();
        let expected = KeyRegistryStateV1::new();
        let mut callback_called = false;
        let mut create_event = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            callback_called = true;
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        let error = store
            .append_signed_authorized(timeline.id(), &expected, &mut create_event)
            .test_err();
        assert!(error.to_string().contains("changed during signing"));
        assert!(!callback_called);
    }

    #[test]
    fn memory_ledger_initialization_covers_registry_and_rollback_boundaries() {
        let mut persisted = KeyRegistryStateV1::new();
        persisted
            .register_key(KeyRegistrationV1::new(
                KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1),
                Hash::from_bytes([3; 32]),
                Some(PublicKey::from_bytes([4; 32])),
            ))
            .test_ok();

        let mut missing_parent = new_store();
        let orphan = TimelineMeta::forked_from(TimelineId::new(), Seq::ZERO, "orphan");
        assert!(missing_parent
            .initialize_timeline_with_key_registry_for_host_transition_unchecked(
                &orphan,
                &KeyRegistryStateV1::new(),
            )
            .is_err());

        let mut mismatch = new_store();
        mismatch.save_key_registry(&persisted).test_ok();
        assert!(mismatch
            .initialize_timeline_with_key_registry("mismatch", &KeyRegistryStateV1::new(),)
            .is_err());
        assert!(mismatch.list_timelines().test_ok().is_empty());

        let mut existing = new_store();
        let existing_timeline = existing.create_timeline("existing").test_ok();
        let reused = existing
            .initialize_timeline_with_key_registry("existing", &KeyRegistryStateV1::new())
            .test_ok();
        assert_eq!(reused.id(), existing_timeline.id());
        assert_eq!(
            existing.load_key_registry().test_ok(),
            Some(KeyRegistryStateV1::new())
        );

        let mut existing_invalid = new_store();
        existing_invalid
            .create_timeline("existing-invalid")
            .test_ok();
        assert!(existing_invalid
            .initialize_timeline_with_key_registry(
                "existing-invalid",
                &super::coverage_entrypoints::invalid_registry(),
            )
            .is_err());

        let mut already_registered = new_store();
        already_registered.save_key_registry(&persisted).test_ok();
        let created = already_registered
            .initialize_timeline_with_key_registry("new-ledger", &persisted)
            .test_ok();
        assert_eq!(created.meta.name.as_deref(), Some("new-ledger"));

        let mut rollback = new_store();
        assert!(rollback
            .initialize_timeline_with_key_registry(
                "invalid-registry",
                &super::coverage_entrypoints::invalid_registry(),
            )
            .is_err());
        assert!(rollback.list_timelines().test_ok().is_empty());

        let mut rollback_failure = new_store();
        fail_next_visible_delete_for_test();
        let error = rollback_failure
            .initialize_timeline_with_key_registry(
                "rollback-failure",
                &super::coverage_entrypoints::invalid_registry(),
            )
            .test_err();
        assert!(error.to_string().contains("rollback also failed"));
    }

    #[test]
    fn memory_effect_read_rejects_a_mismatched_stored_digest() {
        let mut store = new_store();
        let manifest = ErasureReferenceV1::from_digest([1; 32]);
        let effect = pos_core::ErasureCasEffectV1::None;
        let bytes = effect.to_canonical_cbor().test_ok();
        store
            .erasure_effects
            .insert(manifest, (ErasureReferenceV1::from_digest([2; 32]), bytes));
        assert!(store.read_effect(manifest).is_err());
    }

    #[test]
    fn memory_erasure_staging_accepts_only_exact_duplicates() {
        let manifest = ErasureReferenceV1::from_digest([1; 32]);
        let effect = pos_core::ErasureCasEffectV1::None;
        let bytes = effect.to_canonical_cbor().test_ok();

        let reference = ErasureReferenceV1::from_digest([2; 32]);
        let mut exact = BTreeMap::new();
        let mut staged_exact = BTreeMap::new();
        assert!(stage_exact(&exact, &mut staged_exact, reference, b"first").is_ok());
        assert!(stage_exact(&exact, &mut staged_exact, reference, b"first").is_ok());
        assert_eq!(
            stage_exact(&exact, &mut staged_exact, reference, b"second"),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        exact.insert(reference, b"first".to_vec());
        assert!(stage_exact(&exact, &mut BTreeMap::new(), reference, b"first").is_ok());
        assert_eq!(
            stage_exact(&exact, &mut BTreeMap::new(), reference, b"second"),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        let mut effects = BTreeMap::new();
        assert!(insert_effect_exact(&mut effects, manifest, &effect, &bytes).is_ok());
        assert!(insert_effect_exact(&mut effects, manifest, &effect, &bytes).is_ok());

        let other = pos_core::ErasureCasEffectV1::ReceiptAdmission {
            receipt: ErasureReferenceV1::from_digest([2; 32]),
        };
        let other_bytes = other.to_canonical_cbor().test_ok();
        assert!(insert_effect_exact(&mut effects, manifest, &other, &other_bytes).is_err());
        assert!(stage_effect(&effects, &mut BTreeMap::new(), manifest, &effect, &bytes,).is_ok());
        assert_eq!(
            stage_effect(
                &effects,
                &mut BTreeMap::new(),
                manifest,
                &other,
                &other_bytes,
            ),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        let mut staged_effects = BTreeMap::new();
        assert!(stage_effect(
            &BTreeMap::new(),
            &mut staged_effects,
            manifest,
            &effect,
            &bytes,
        )
        .is_ok());
        assert!(stage_effect(
            &BTreeMap::new(),
            &mut staged_effects,
            manifest,
            &effect,
            &bytes,
        )
        .is_ok());
        assert_eq!(
            stage_effect(
                &BTreeMap::new(),
                &mut staged_effects,
                manifest,
                &other,
                &other_bytes,
            ),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        assert_eq!(
            decode_memory_effect(&(effect.identity(), vec![0xff])),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            decode_memory_effect(&(ErasureReferenceV1::from_digest([9; 32]), bytes.clone())),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        let request = ErasureReferenceV1::from_digest([3; 32]);
        let mut indexes = BTreeMap::new();
        let first = ErasureReferenceV1::from_digest([4; 32]);
        let second = ErasureReferenceV1::from_digest([5; 32]);
        assert!(insert_index(&mut indexes, request, 0, first).is_ok());
        assert!(insert_index(&mut indexes, request, 0, first).is_ok());
        assert_eq!(
            insert_index(&mut indexes, request, 0, second),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut staged_indexes = BTreeMap::new();
        assert!(stage_index(&BTreeMap::new(), &mut staged_indexes, request, 0, first,).is_ok());
        assert!(stage_index(&BTreeMap::new(), &mut staged_indexes, request, 0, first,).is_ok());
        assert_eq!(
            stage_index(&BTreeMap::new(), &mut staged_indexes, request, 0, second,),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert!(stage_index(&indexes, &mut BTreeMap::new(), request, 0, first,).is_ok());
        assert_eq!(
            stage_index(&indexes, &mut BTreeMap::new(), request, 0, second,),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }

    #[test]
    fn memory_effect_subject_staging_preserves_exact_identity() {
        let subject = ErasureReferenceV1::from_digest([1; 32]);
        let manifest = ErasureReferenceV1::from_digest([2; 32]);
        let conflicting = ErasureReferenceV1::from_digest([3; 32]);
        let mut staged = BTreeMap::new();

        assert!(stage_effect_subject(&BTreeMap::new(), &mut staged, None, manifest).is_ok());
        assert!(staged.is_empty());
        assert!(
            stage_effect_subject(&BTreeMap::new(), &mut staged, Some(subject), manifest,).is_ok()
        );
        assert_eq!(staged.get(&subject), Some(&manifest));

        let existing = BTreeMap::from([(subject, manifest)]);
        assert!(
            stage_effect_subject(&existing, &mut BTreeMap::new(), Some(subject), manifest,).is_ok()
        );
        assert_eq!(
            stage_effect_subject(&existing, &mut BTreeMap::new(), Some(subject), conflicting,),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_boundary_rejects_non_v1_serialized_draft() {
        let draft = make_draft(EntityId::new(), b"payload");
        let mut encoded = serde_json::to_value(draft).test_ok();
        encoded["schema_version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<EventDraft>(encoded).is_err());
    }
}

impl ArtifactRegistrationPersistencePortV1 for MemoryStore {
    fn commit_artifact_registration_batch(
        &mut self,
        batch: PreparedArtifactRegistrationBatchV1,
    ) -> Result<ArtifactRegistrationCommitOutcomeV1, ArtifactRegistrationPersistenceErrorV1> {
        let root_registration_address = batch.root_registration_address();
        let has_root_record = batch.records().iter().any(|record| {
            let same_owner = record.owner_id() == batch.owner_id();
            let same_address = record.registration_address() == root_registration_address;
            same_owner && same_address
        });
        if batch.records().is_empty() || !has_root_record {
            return Err(ArtifactRegistrationPersistenceErrorV1::StorageFailure);
        }

        let operation_key = (*batch.owner_id(), batch.root_operation_id());
        let mut rows = Vec::with_capacity(batch.records().len());
        let mut has_new_rows = false;
        for record in batch.records() {
            let row = ArtifactRegistrationCatalogRowV1::from_persisted(
                *record.owner_id(),
                record.artifact_class(),
                record.artifact_digest(),
                record.registration_address(),
                record.artifact_bytes().to_vec(),
                record.registration().canonical_cbor(),
            )?;
            let address_key = row.registration_address();
            let identity_key = (*row.owner_id(), row.artifact_class(), row.artifact_digest());
            match (
                self.artifact_registrations.get(&address_key),
                self.artifact_registration_identities.get(&identity_key),
            ) {
                (None, None) => has_new_rows = true,
                (Some(existing), Some(address))
                    if existing == &row && *address == row.registration_address() => {}
                (None | Some(_), Some(_)) | (Some(_), None) => {
                    return Err(ArtifactRegistrationPersistenceErrorV1::Conflict);
                }
            }
            rows.push((address_key, identity_key, row));
        }

        let graph_nodes: Vec<_> = rows
            .iter()
            .map(|(address, _, row)| ArtifactRegistrationGraphNodeV1 {
                address: *address,
                owner_id: *row.owner_id(),
                artifact_class: row.artifact_class(),
                artifact_digest: row.artifact_digest(),
                registration: row.registration().clone(),
            })
            .collect();
        inspect_artifact_registration_graph_v1(batch.root_registration_address(), &graph_nodes)
            .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;

        let root_row = rows
            .iter()
            .find(|(address, _, _)| *address == batch.root_registration_address())
            .map(|(_, _, row)| row)
            .ok_or(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
        let root = ReproManifestRootV1::from_canonical_cbor(root_row.artifact_bytes())
            .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
        if root.as_input().run_operation_id != batch.root_operation_id()
            || root_row.owner_id() != batch.owner_id()
        {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
        let transcript_bytes =
            find_memory_root_transcript_bytes(rows.iter().map(|(_, _, row)| row), &root)?;
        self.validate_root_adapter_recording(&root, transcript_bytes)?;

        self.check_artifact_registration_operation(
            operation_key,
            batch.root_registration_address(),
        )?;

        for (address_key, identity_key, row) in rows {
            self.artifact_registrations
                .entry(address_key)
                .or_insert(row);
            self.artifact_registration_identities
                .entry(identity_key)
                .or_insert(address_key);
        }
        self.artifact_registration_operations
            .entry(operation_key)
            .or_insert(root_registration_address);
        Ok(if has_new_rows {
            ArtifactRegistrationCommitOutcomeV1::Applied
        } else {
            ArtifactRegistrationCommitOutcomeV1::ExactRetry
        })
    }

    fn read_artifact_registration(
        &self,
        owner_id: &OwnerIdV1,
        registration_address: Hash,
    ) -> Result<Option<ArtifactRegistrationCatalogRowV1>, ArtifactRegistrationPersistenceErrorV1>
    {
        let Some(row) = self.artifact_registrations.get(&registration_address) else {
            let indexed_without_row = self.artifact_registration_identities.iter().any(
                |((stored_owner, _, _), address)| {
                    stored_owner == owner_id && *address == registration_address
                },
            ) || self.artifact_registration_operations.iter().any(
                |((stored_owner, _), address)| {
                    stored_owner == owner_id && *address == registration_address
                },
            );
            return if indexed_without_row {
                Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
            } else {
                Ok(None)
            };
        };
        if row.owner_id() != owner_id {
            return Ok(None);
        }
        self.validate_artifact_registration_closure(registration_address)?;
        Ok(Some(row.clone()))
    }
}

struct MemoryManifestOwnerGenerationEvidenceV1 {
    operation_id: Hash,
    inventory_generation: Hash,
    previous_visible_lcq1_hash: Option<Hash>,
    receipt_hashes: Vec<Hash>,
}

fn memory_manifest_owner_state_has_orphaned_rows(store: &MemoryStore, owner_id: [u8; 32]) -> bool {
    store
        .manifest_owner_admission_snapshots
        .keys()
        .any(|(stored_owner, _, _)| *stored_owner == owner_id)
        || store
            .manifest_owner_admission_operations
            .keys()
            .any(|(stored_owner, _)| *stored_owner == owner_id)
        || store.local_cut_owner_states.contains_key(&owner_id)
        || store
            .local_cut_owner_operations
            .keys()
            .any(|(stored_owner, _)| *stored_owner == owner_id)
        || store
            .local_cut_owner_commits
            .keys()
            .any(|(stored_owner, _)| *stored_owner == owner_id)
}

fn memory_validate_manifest_owner_state_header(
    store: &MemoryStore,
    owner_id: [u8; 32],
    state: &MemoryManifestOwnerAdmissionStateV1,
) -> Result<bool, ManifestOwnerAdmissionErrorV1> {
    if state.configuration_generation == 0
        || state.timelines.is_empty()
        || state.inventory_generation == Hash::zero()
        || state.previous_visible_lcq1_hash == Some(Hash::zero())
    {
        return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
    }
    let Some(local_cut_state) = store.local_cut_owner_states.get(&owner_id) else {
        let has_orphaned_local_cut_rows = store
            .local_cut_owner_operations
            .keys()
            .any(|(stored_owner, _)| *stored_owner == owner_id)
            || store
                .local_cut_owner_commits
                .keys()
                .any(|(stored_owner, _)| *stored_owner == owner_id);
        return if has_orphaned_local_cut_rows {
            Err(ManifestOwnerAdmissionErrorV1::CorruptState)
        } else {
            Ok(false)
        };
    };
    local_cut_state
        .validate()
        .map_err(|_| ManifestOwnerAdmissionErrorV1::CorruptState)?;
    if local_cut_state.owner_id != owner_id
        || local_cut_state.configuration_generation != state.configuration_generation
        || local_cut_state.previous_visible_lcq1_hash != state.previous_visible_lcq1_hash
        || local_cut_state.inventory_generation != state.inventory_generation
        || local_cut_state
            .timelines
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != state.timelines
    {
        return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
    }
    Ok(true)
}

fn memory_collect_manifest_owner_generation_evidence(
    store: &MemoryStore,
    owner_id: [u8; 32],
    state: &MemoryManifestOwnerAdmissionStateV1,
) -> Result<MemoryManifestOwnerGenerationEvidenceV1, ManifestOwnerAdmissionErrorV1> {
    let current_generation_rows = store
        .manifest_owner_admission_snapshots
        .keys()
        .filter(|(stored_owner, generation, _)| {
            *stored_owner == owner_id && *generation == state.configuration_generation
        })
        .count();
    if current_generation_rows != state.timelines.len() {
        return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
    }
    // A missing snapshot empties the list; the header already rejected an
    // empty roster, so an absent first snapshot always means a missing row.
    let snapshots = state
        .timelines
        .iter()
        .map(|timeline_id| {
            store.manifest_owner_admission_snapshots.get(&(
                owner_id,
                state.configuration_generation,
                *timeline_id,
            ))
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    let first = snapshots
        .first()
        .copied()
        .ok_or(ManifestOwnerAdmissionErrorV1::CorruptState)?;
    let catalog_hash = first.catalog.digest();
    let first_receipt = first.timeline.receipt.as_input();
    let previous_visible_lcq1_hash = first_receipt.previous_visible_lcq1_hash;
    let mut scopes = HashSet::with_capacity(snapshots.len());
    let mut receipt_hashes = Vec::with_capacity(snapshots.len());
    for (snapshot, timeline_id) in snapshots.iter().zip(&state.timelines) {
        let receipt = snapshot.timeline.receipt.as_input();
        if snapshot.timeline.timeline_id != *timeline_id
            || snapshot.operation_id != first.operation_id
            || snapshot.catalog.digest() != catalog_hash
            || snapshot.resulting_inventory_generation != first.resulting_inventory_generation
            || receipt.previous_visible_lcq1_hash != previous_visible_lcq1_hash
            || !scopes.insert(snapshot.timeline.scope)
            || validate_manifest_owner_admission_snapshot_v1(snapshot).is_err()
        {
            return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
        }
        receipt_hashes.push(snapshot.timeline.receipt.digest());
    }
    Ok(MemoryManifestOwnerGenerationEvidenceV1 {
        operation_id: first.operation_id,
        inventory_generation: first.resulting_inventory_generation,
        previous_visible_lcq1_hash,
        receipt_hashes,
    })
}

fn memory_validate_manifest_owner_generation_operation(
    store: &MemoryStore,
    owner_id: [u8; 32],
    state: &MemoryManifestOwnerAdmissionStateV1,
    evidence: &MemoryManifestOwnerGenerationEvidenceV1,
    has_local_cut_state: bool,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    if !has_local_cut_state
        && (evidence.inventory_generation != state.inventory_generation
            || evidence.previous_visible_lcq1_hash != state.previous_visible_lcq1_hash)
    {
        return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
    }
    let operation = store
        .manifest_owner_admission_operations
        .get(&(owner_id, evidence.operation_id))
        .ok_or(ManifestOwnerAdmissionErrorV1::CorruptState)?;
    if operation.result.kind != ManifestOwnerAdmissionCommitKindV1::Applied
        || operation.result.configuration_generation != state.configuration_generation
        || operation.result.inventory_generation != evidence.inventory_generation
        || operation.result.receipt_hashes != evidence.receipt_hashes
        || store
            .manifest_owner_admission_operations
            .iter()
            .filter(|((stored_owner, _), operation)| {
                *stored_owner == owner_id
                    && operation.result.configuration_generation == state.configuration_generation
            })
            .count()
            != 1
    {
        return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
    }
    Ok(())
}

/// Derive the local-cut owner successor for a committed successor admission.
///
/// The caller has just read the owner state, which validated the local-cut
/// state against the admitted header, and matched that header against the
/// input's expected generation, receipt, and inventory.
fn memory_successor_local_cut_owner_state(
    store: &MemoryStore,
    owner_id: [u8; 32],
    input: &pos_core::ManifestOwnerAdmissionInputV1,
    next_state: &MemoryManifestOwnerAdmissionStateV1,
) -> Result<Option<LocalCutOwnerStateV1>, ManifestOwnerAdmissionErrorV1> {
    let Some(local_cut_state) = store.local_cut_owner_states.get(&owner_id) else {
        return Ok(None);
    };
    let next_timelines = next_state.timelines.iter().copied().collect::<Vec<_>>();
    let membership_epoch = if local_cut_state.timelines == next_timelines {
        local_cut_state.membership_epoch
    } else {
        local_cut_state
            .membership_epoch
            .checked_add(1)
            .ok_or(ManifestOwnerAdmissionErrorV1::Conflict)?
    };
    let successor = LocalCutOwnerStateV1 {
        owner_id,
        last_visible_cut_id: local_cut_state.last_visible_cut_id,
        last_visible_tick: local_cut_state.last_visible_tick,
        membership_epoch,
        configuration_generation: input.catalog.as_input().configuration_generation,
        previous_visible_lcq1_hash: input.previous_visible_lcq1_hash,
        inventory_generation: input.resulting_inventory_generation,
        timelines: next_timelines,
    };
    successor
        .validate()
        .map_err(|_| ManifestOwnerAdmissionErrorV1::CorruptState)?;
    Ok(Some(successor))
}

impl ManifestOwnerAdmissionPersistencePortV1 for MemoryStore {
    fn read_manifest_owner_state_v1(
        &self,
        owner_id: [u8; 32],
    ) -> Result<Option<ManifestOwnerAdmissionOwnerStateV1>, ManifestOwnerAdmissionErrorV1> {
        let Some(state) = self.manifest_owner_admission_states.get(&owner_id) else {
            return if memory_manifest_owner_state_has_orphaned_rows(self, owner_id) {
                Err(ManifestOwnerAdmissionErrorV1::CorruptState)
            } else {
                Ok(None)
            };
        };
        let has_local_cut_state =
            memory_validate_manifest_owner_state_header(self, owner_id, state)?;
        let evidence = memory_collect_manifest_owner_generation_evidence(self, owner_id, state)?;
        memory_validate_manifest_owner_generation_operation(
            self,
            owner_id,
            state,
            &evidence,
            has_local_cut_state,
        )?;
        Ok(Some(ManifestOwnerAdmissionOwnerStateV1 {
            owner_id,
            configuration_generation: state.configuration_generation,
            previous_visible_lcq1_hash: state.previous_visible_lcq1_hash,
            inventory_generation: state.inventory_generation,
            timelines: state.timelines.iter().copied().collect(),
        }))
    }

    fn resolve_manifest_owner_admission_retry_v1(
        &self,
        owner_id: [u8; 32],
        operation_id: Hash,
        intent_digest: Hash,
    ) -> Result<Option<ManifestOwnerAdmissionCommitV1>, ManifestOwnerAdmissionErrorV1> {
        self.read_manifest_owner_state_v1(owner_id)?;
        let Some(operation) = self
            .manifest_owner_admission_operations
            .get(&(owner_id, operation_id))
        else {
            return Ok(None);
        };
        if operation.intent_digest != intent_digest {
            return Err(ManifestOwnerAdmissionErrorV1::Conflict);
        }
        let result = &operation.result;
        if result.kind != ManifestOwnerAdmissionCommitKindV1::Applied
            || result.configuration_generation == 0
            || result.inventory_generation == Hash::zero()
            || result.receipt_hashes.is_empty()
        {
            return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
        }
        let mut receipt_hashes = Vec::with_capacity(result.receipt_hashes.len());
        let mut row_count = 0;
        for ((stored_owner, generation, timeline_id), snapshot) in
            &self.manifest_owner_admission_snapshots
        {
            if *stored_owner == owner_id && *generation == result.configuration_generation {
                row_count += 1;
                if snapshot.operation_id != operation_id
                    || snapshot.timeline.timeline_id != *timeline_id
                    || snapshot.resulting_inventory_generation != result.inventory_generation
                    || validate_manifest_owner_admission_snapshot_v1(snapshot).is_err()
                {
                    return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
                }
                receipt_hashes.push(snapshot.timeline.receipt.digest());
            }
        }
        if row_count != result.receipt_hashes.len() || receipt_hashes != result.receipt_hashes {
            return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
        }
        let mut retry = result.clone();
        retry.kind = ManifestOwnerAdmissionCommitKindV1::ExactRetry;
        Ok(Some(retry))
    }

    fn commit_manifest_owner_admission_v1(
        &mut self,
        batch: PreparedManifestOwnerAdmissionV1,
    ) -> Result<ManifestOwnerAdmissionCommitV1, ManifestOwnerAdmissionErrorV1> {
        let input = batch.input();
        let owner_id = input.catalog.as_input().owner_id;
        let current_state = self.read_manifest_owner_state_v1(owner_id)?;
        if let Some(result) = self.resolve_manifest_owner_admission_retry_v1(
            owner_id,
            input.operation_id,
            batch.intent_digest(),
        )? {
            return Ok(result);
        }

        match (input.expected_configuration_generation, current_state) {
            (None, None) => {}
            (Some(expected_generation), Some(state))
                if state.configuration_generation == expected_generation
                    && state.previous_visible_lcq1_hash == input.previous_visible_lcq1_hash
                    && Some(state.inventory_generation) == input.expected_inventory_generation
                    && !state.timelines.is_empty()
                    && expected_generation.checked_add(1)
                        == Some(input.catalog.as_input().configuration_generation) => {}
            _ => return Err(ManifestOwnerAdmissionErrorV1::Conflict),
        }

        let configuration_generation = input.catalog.as_input().configuration_generation;
        if input.timelines.iter().any(|timeline| {
            self.manifest_owner_admission_snapshots.contains_key(&(
                owner_id,
                configuration_generation,
                timeline.timeline_id,
            ))
        }) {
            return Err(ManifestOwnerAdmissionErrorV1::Conflict);
        }

        let result = ManifestOwnerAdmissionCommitV1 {
            kind: ManifestOwnerAdmissionCommitKindV1::Applied,
            configuration_generation,
            inventory_generation: input.resulting_inventory_generation,
            receipt_hashes: input
                .timelines
                .iter()
                .map(|timeline| timeline.receipt.digest())
                .collect(),
        };
        let snapshots: Vec<_> = input
            .timelines
            .iter()
            .map(|timeline| {
                (
                    (owner_id, configuration_generation, timeline.timeline_id),
                    ManifestOwnerAdmissionSnapshotV1 {
                        catalog: input.catalog.clone(),
                        timeline: timeline.clone(),
                        operation_id: input.operation_id,
                        expected_inventory_generation: input.expected_inventory_generation,
                        resulting_inventory_generation: input.resulting_inventory_generation,
                    },
                )
            })
            .collect();
        let next_state = MemoryManifestOwnerAdmissionStateV1 {
            configuration_generation,
            previous_visible_lcq1_hash: input.previous_visible_lcq1_hash,
            inventory_generation: input.resulting_inventory_generation,
            timelines: input
                .timelines
                .iter()
                .map(|timeline| timeline.timeline_id)
                .collect(),
        };
        let next_local_cut_owner_state =
            memory_successor_local_cut_owner_state(self, owner_id, input, &next_state)?;
        let operation = MemoryManifestOwnerAdmissionOperationV1 {
            intent_digest: batch.intent_digest(),
            result: result.clone(),
        };

        for (key, snapshot) in snapshots {
            self.manifest_owner_admission_snapshots
                .insert(key, snapshot);
        }
        self.manifest_owner_admission_states
            .insert(owner_id, next_state);
        if let Some(next_local_cut_owner_state) = next_local_cut_owner_state {
            self.local_cut_owner_states
                .insert(owner_id, next_local_cut_owner_state);
        }
        self.manifest_owner_admission_operations
            .insert((owner_id, input.operation_id), operation);
        Ok(result)
    }

    fn read_manifest_owner_admission_v1(
        &self,
        owner_id: [u8; 32],
        configuration_generation: u64,
        timeline_id: TimelineId,
    ) -> Result<Option<ManifestOwnerAdmissionSnapshotV1>, ManifestOwnerAdmissionErrorV1> {
        let Some(snapshot) = self.manifest_owner_admission_snapshots.get(&(
            owner_id,
            configuration_generation,
            timeline_id,
        )) else {
            return Ok(None);
        };
        if snapshot.catalog.as_input().owner_id != owner_id
            || snapshot.catalog.as_input().configuration_generation != configuration_generation
            || snapshot.timeline.timeline_id != timeline_id
            || snapshot.timeline.receipt.digest() == Hash::zero()
            || snapshot.resulting_inventory_generation == Hash::zero()
            || validate_manifest_owner_admission_snapshot_v1(snapshot).is_err()
        {
            return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
        }
        let operation = self
            .manifest_owner_admission_operations
            .get(&(owner_id, snapshot.operation_id))
            .ok_or(ManifestOwnerAdmissionErrorV1::CorruptState)?;
        if operation.result.configuration_generation != configuration_generation
            || operation.result.inventory_generation != snapshot.resulting_inventory_generation
        {
            return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
        }
        let mut generation_receipts = Vec::new();
        let mut generation_operations = 0_usize;
        for ((stored_owner, stored_operation_id), stored_operation) in
            &self.manifest_owner_admission_operations
        {
            if *stored_owner == owner_id
                && stored_operation.result.configuration_generation == configuration_generation
            {
                generation_operations += 1;
                if *stored_operation_id != snapshot.operation_id {
                    return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
                }
            }
        }
        for ((stored_owner, stored_generation, stored_timeline), stored_snapshot) in
            &self.manifest_owner_admission_snapshots
        {
            if *stored_owner != owner_id || *stored_generation != configuration_generation {
                continue;
            }
            if stored_snapshot.operation_id != snapshot.operation_id
                || stored_snapshot.resulting_inventory_generation
                    != snapshot.resulting_inventory_generation
                || stored_snapshot
                    .timeline
                    .receipt
                    .as_input()
                    .previous_visible_lcq1_hash
                    != snapshot
                        .timeline
                        .receipt
                        .as_input()
                        .previous_visible_lcq1_hash
                || validate_manifest_owner_admission_snapshot_v1(stored_snapshot).is_err()
            {
                return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
            }
            generation_receipts.push(stored_snapshot.timeline.receipt.digest());
            if *stored_timeline == timeline_id
                && stored_snapshot.timeline.receipt.digest() != snapshot.timeline.receipt.digest()
            {
                return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
            }
        }
        if generation_operations != 1
            || generation_receipts.is_empty()
            || generation_receipts != operation.result.receipt_hashes
        {
            return Err(ManifestOwnerAdmissionErrorV1::CorruptState);
        }
        Ok(Some(snapshot.clone()))
    }
}

fn validate_memory_local_cut_operation(
    owner_id: [u8; 32],
    operation_id: Hash,
    operation: &MemoryLocalCutOwnerOperationV1,
    commits: &BTreeMap<([u8; 32], u64), LocalCutOwnerCommitV1>,
) -> Result<(), LocalCutOwnerErrorV1> {
    if local_cut_owner_intent_digest_v1(&operation.request)? != operation.intent_digest {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    let cut_id = operation.request.seal.as_input().cut_id;
    validate_local_cut_owner_result_v1(owner_id, cut_id, &operation.result)?;
    let commit = operation.result.commit.as_input();
    if operation.request.operation_id != operation_id
        || operation.result.seal != operation.request.seal
        || commit.partition_ledger_seq != operation.request.partition_ledger_seq
        || commit.manifest_hash != operation.request.manifest_hash
        || commit.result_heads_table != operation.request.result_heads_table
        || commit.participant_successor_table != operation.request.participant_successor_table
        || commit.cpu_completion_table != operation.request.cpu_completion_table
        || commit.action_disposition_table != operation.request.action_disposition_table
        || commit.candidate_bases_table != operation.request.candidate_bases_table
        || commit.invocation_bridges_table != operation.request.invocation_bridges_table
        || commit.result_inventory_generation != operation.request.result_inventory_generation
        || commit.release_fence_proof_digest != operation.request.release_fence_proof_digest
        || commits.get(&(owner_id, cut_id)) != Some(&operation.result)
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(())
}

impl LocalCutOwnerPersistencePortV1 for MemoryStore {
    fn read_local_cut_owner_state_v1(
        &self,
        owner_id: [u8; 32],
    ) -> Result<Option<LocalCutOwnerStateV1>, LocalCutOwnerErrorV1> {
        let Some(state) = self.local_cut_owner_states.get(&owner_id) else {
            let has_rows = self
                .local_cut_owner_operations
                .keys()
                .any(|(stored_owner, _)| *stored_owner == owner_id)
                || self
                    .local_cut_owner_commits
                    .keys()
                    .any(|(stored_owner, _)| *stored_owner == owner_id);
            return if has_rows {
                Err(LocalCutOwnerErrorV1::CorruptState)
            } else {
                Ok(None)
            };
        };
        state.validate()?;
        // The memory admission read only fails with CorruptState. It also checks
        // this local-cut state against the admitted header, and rejects a
        // local-cut state without an admitted header as orphaned.
        self.read_manifest_owner_state_v1(owner_id)?;

        let mut found_current = false;
        for ((stored_owner, cut_id), result) in &self.local_cut_owner_commits {
            if *stored_owner != owner_id {
                continue;
            }
            validate_local_cut_owner_result_v1(owner_id, *cut_id, result)?;
            if *cut_id > state.last_visible_cut_id {
                return Err(LocalCutOwnerErrorV1::CorruptState);
            }
            if *cut_id == state.last_visible_cut_id {
                if state.previous_visible_lcq1_hash != Some(result.receipt.digest()) {
                    return Err(LocalCutOwnerErrorV1::CorruptState);
                }
                found_current = true;
            }
            let linked_operations = self
                .local_cut_owner_operations
                .iter()
                .filter(|((stored_owner, _), operation)| {
                    *stored_owner == owner_id
                        && operation.request.seal.as_input().cut_id == *cut_id
                        && operation.result == *result
                })
                .count();
            if linked_operations != 1 {
                return Err(LocalCutOwnerErrorV1::CorruptState);
            }
        }
        if !found_current {
            return Err(LocalCutOwnerErrorV1::CorruptState);
        }
        for ((stored_owner, operation_id), operation) in &self.local_cut_owner_operations {
            if *stored_owner == owner_id {
                validate_memory_local_cut_operation(
                    owner_id,
                    *operation_id,
                    operation,
                    &self.local_cut_owner_commits,
                )?;
            }
        }
        Ok(Some(state.clone()))
    }

    fn resolve_local_cut_owner_retry_v1(
        &self,
        owner_id: [u8; 32],
        operation_id: Hash,
        intent_digest: Hash,
    ) -> Result<Option<LocalCutOwnerCommitV1>, LocalCutOwnerErrorV1> {
        self.read_local_cut_owner_state_v1(owner_id)?;
        let Some(operation) = self
            .local_cut_owner_operations
            .get(&(owner_id, operation_id))
        else {
            return Ok(None);
        };
        // The owner-state read above already validated every retained operation.
        if operation.intent_digest != intent_digest {
            return Err(LocalCutOwnerErrorV1::Conflict);
        }
        let mut retry = operation.result.clone();
        retry.kind = LocalCutOwnerCommitKindV1::ExactRetry;
        Ok(Some(retry))
    }

    fn commit_local_cut_owner_v1(
        &mut self,
        batch: PreparedLocalCutOwnerCommitV1,
    ) -> Result<LocalCutOwnerCommitV1, LocalCutOwnerErrorV1> {
        let owner_id = batch.successor_state().owner_id;
        let operation_id = batch.request().operation_id;
        let intent_digest = batch.intent_digest();
        let result = batch.applied_result();
        let current_state = self.read_local_cut_owner_state_v1(owner_id)?;
        if let Some(retry) =
            self.resolve_local_cut_owner_retry_v1(owner_id, operation_id, intent_digest)?
        {
            return Ok(retry);
        }
        let admission = self
            .read_manifest_owner_state_v1(owner_id)?
            .ok_or(LocalCutOwnerErrorV1::Conflict)?;
        validate_local_cut_owner_successor_v1(&batch, &admission, current_state.as_ref())?;
        let request = batch.request();
        let successor = batch.successor_state();
        // The owner-state read bounds every retained cut by the last visible cut,
        // and the successor cut is strictly newer, so this key is unused.
        let cut_id = request.seal.as_input().cut_id;
        let operation = MemoryLocalCutOwnerOperationV1 {
            intent_digest,
            request: request.clone(),
            result: result.clone(),
        };
        let next_admission_state = MemoryManifestOwnerAdmissionStateV1 {
            configuration_generation: admission.configuration_generation,
            previous_visible_lcq1_hash: Some(result.receipt.digest()),
            inventory_generation: request.result_inventory_generation,
            timelines: admission.timelines.iter().copied().collect(),
        };

        self.local_cut_owner_commits
            .insert((owner_id, cut_id), result.clone());
        self.local_cut_owner_operations
            .insert((owner_id, operation_id), operation);
        self.local_cut_owner_states
            .insert(owner_id, successor.clone());
        self.manifest_owner_admission_states
            .insert(owner_id, next_admission_state);
        Ok(result)
    }

    fn read_local_cut_owner_commit_v1(
        &self,
        owner_id: [u8; 32],
        cut_id: u64,
    ) -> Result<Option<LocalCutOwnerCommitV1>, LocalCutOwnerErrorV1> {
        // The owner-state read validates every retained cut and its one
        // linked operation.
        self.read_local_cut_owner_state_v1(owner_id)?;
        Ok(self
            .local_cut_owner_commits
            .get(&(owner_id, cut_id))
            .cloned())
    }
}

impl AdapterRecordingStoreV1 for MemoryStore {
    fn open_adapter_recording_session(
        &mut self,
        session: AdapterRecordingSessionV1,
    ) -> Result<(), AdapterRecordingStoreErrorV1> {
        let key = (session.owner_reference(), session.run_operation_id());
        match self.adapter_recording_sessions.get(&key) {
            Some(existing) if existing.session != session => {
                Err(AdapterRecordingStoreErrorV1::Conflict)
            }
            Some(existing) if existing.status == MemoryAdapterRecordingStatusV1::Open => Ok(()),
            Some(_) => Err(AdapterRecordingStoreErrorV1::InvalidState),
            None => {
                self.adapter_recording_sessions.insert(
                    key,
                    MemoryAdapterRecordingSessionV1 {
                        session,
                        status: MemoryAdapterRecordingStatusV1::Open,
                        calls: BTreeMap::new(),
                        transcript_bytes: None,
                    },
                );
                Ok(())
            }
        }
    }

    fn reserve_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        reservation: AdapterCallReservationV1,
    ) -> Result<AdapterCallReservationOutcomeV1, AdapterRecordingStoreErrorV1> {
        let key = (owner_reference, run_operation_id);
        let journal = self
            .adapter_recording_sessions
            .get_mut(&key)
            .ok_or(AdapterRecordingStoreErrorV1::InvalidState)?;
        if journal.status != MemoryAdapterRecordingStatusV1::Open
            || journal.session.owner_reference() != owner_reference
        {
            return Err(AdapterRecordingStoreErrorV1::InvalidState);
        }
        let global_index = reservation.invocation().as_input().global_call_index;
        if let Some(existing) = journal.calls.get(&global_index) {
            if !same_memory_adapter_reservation(&existing.reservation, &reservation) {
                return Err(AdapterRecordingStoreErrorV1::InvalidCall);
            }
            return Ok(existing.output_bytes.as_ref().map_or_else(
                || AdapterCallReservationOutcomeV1::Reserved {
                    reserved_at_micros: existing.reservation.reserved_at_micros(),
                },
                |output_bytes| AdapterCallReservationOutcomeV1::Completed {
                    output_bytes: output_bytes.clone(),
                    reserved_at_micros: existing.reservation.reserved_at_micros(),
                },
            ));
        }
        let expected_index = u64::try_from(journal.calls.len())
            .map_err(|_| AdapterRecordingStoreErrorV1::InvalidCall)?;
        if global_index != expected_index
            || journal.calls.len() >= pos_core::MAX_ADAPTER_TRANSCRIPT_CALLS_V1
        {
            return Err(AdapterRecordingStoreErrorV1::InvalidCall);
        }
        let expected_plugin_index = journal
            .calls
            .values()
            .filter(|call| call.reservation.plugin_id() == reservation.plugin_id())
            .count();
        if usize::try_from(reservation.per_plugin_call_index()).ok() != Some(expected_plugin_index)
        {
            return Err(AdapterRecordingStoreErrorV1::InvalidCall);
        }
        journal.calls.insert(
            global_index,
            MemoryAdapterRecordingCallV1 {
                reservation: reservation.clone(),
                output_bytes: None,
            },
        );
        Ok(AdapterCallReservationOutcomeV1::Reserved {
            reserved_at_micros: reservation.reserved_at_micros(),
        })
    }

    fn complete_adapter_call(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
        global_call_index: u64,
        output_bytes: Vec<u8>,
    ) -> Result<(), AdapterRecordingStoreErrorV1> {
        if output_bytes.len() > pos_core::MAX_ADAPTER_CALL_BYTES_V1 {
            return Err(AdapterRecordingStoreErrorV1::InvalidCall);
        }
        let journal = self
            .adapter_recording_sessions
            .get_mut(&(owner_reference, run_operation_id))
            .ok_or(AdapterRecordingStoreErrorV1::InvalidState)?;
        if journal.status != MemoryAdapterRecordingStatusV1::Open {
            return Err(AdapterRecordingStoreErrorV1::InvalidState);
        }
        let call = journal
            .calls
            .get_mut(&global_call_index)
            .ok_or(AdapterRecordingStoreErrorV1::InvalidCall)?;
        match &call.output_bytes {
            Some(existing) if existing == &output_bytes => Ok(()),
            Some(_) => Err(AdapterRecordingStoreErrorV1::Conflict),
            None => {
                call.output_bytes = Some(output_bytes);
                Ok(())
            }
        }
    }

    fn close_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Vec<u8>, AdapterRecordingStoreErrorV1> {
        let journal = self
            .adapter_recording_sessions
            .get_mut(&(owner_reference, run_operation_id))
            .ok_or(AdapterRecordingStoreErrorV1::InvalidState)?;
        if journal.status == MemoryAdapterRecordingStatusV1::Closed {
            let retained = journal
                .transcript_bytes
                .clone()
                .ok_or(AdapterRecordingStoreErrorV1::CorruptState)?;
            let derived = memory_adapter_recording_transcript(journal)?;
            if retained != derived {
                return Err(AdapterRecordingStoreErrorV1::CorruptState);
            }
            return Ok(retained);
        }
        if journal.status != MemoryAdapterRecordingStatusV1::Open {
            return Err(AdapterRecordingStoreErrorV1::InvalidState);
        }
        let transcript_bytes = memory_adapter_recording_transcript(journal)?;
        journal.status = MemoryAdapterRecordingStatusV1::Closed;
        journal.transcript_bytes = Some(transcript_bytes.clone());
        Ok(transcript_bytes)
    }

    fn read_closed_adapter_recording_session(
        &self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<Option<Vec<u8>>, AdapterRecordingStoreErrorV1> {
        let Some(journal) = self
            .adapter_recording_sessions
            .get(&(owner_reference, run_operation_id))
        else {
            return Ok(None);
        };
        if journal.session.owner_reference() != owner_reference {
            return Err(AdapterRecordingStoreErrorV1::CorruptState);
        }
        if journal.status != MemoryAdapterRecordingStatusV1::Closed {
            return Ok(None);
        }
        let bytes = journal
            .transcript_bytes
            .as_ref()
            .ok_or(AdapterRecordingStoreErrorV1::CorruptState)?;
        if memory_adapter_recording_transcript(journal)?.as_slice() != bytes.as_slice() {
            return Err(AdapterRecordingStoreErrorV1::CorruptState);
        }
        validate_closed_adapter_recording_v1(&journal.session, bytes)?;
        Ok(Some(bytes.clone()))
    }

    fn abort_adapter_recording_session(
        &mut self,
        owner_reference: Hash,
        run_operation_id: Hash,
    ) -> Result<(), AdapterRecordingStoreErrorV1> {
        let journal = self
            .adapter_recording_sessions
            .get_mut(&(owner_reference, run_operation_id))
            .ok_or(AdapterRecordingStoreErrorV1::InvalidState)?;
        if journal.status != MemoryAdapterRecordingStatusV1::Open {
            return Err(AdapterRecordingStoreErrorV1::InvalidState);
        }
        journal.status = MemoryAdapterRecordingStatusV1::Aborted;
        Ok(())
    }
}

fn memory_adapter_recording_transcript(
    journal: &MemoryAdapterRecordingSessionV1,
) -> Result<Vec<u8>, AdapterRecordingStoreErrorV1> {
    let calls = journal
        .calls
        .values()
        .map(|call| {
            call.output_bytes
                .as_ref()
                .map(|output| completed_adapter_call_v1(call.reservation.clone(), output.clone()))
                .ok_or(AdapterRecordingStoreErrorV1::InvalidState)
        })
        .collect::<Result<Vec<AdapterTranscriptCallV1>, _>>()?;
    close_adapter_recording_v1(&journal.session, calls)
}

fn same_memory_adapter_reservation(
    existing: &AdapterCallReservationV1,
    retry: &AdapterCallReservationV1,
) -> bool {
    existing.plugin_id() == retry.plugin_id()
        && existing.per_plugin_call_index() == retry.per_plugin_call_index()
        && existing.invocation() == retry.invocation()
        && existing.idempotency_key() == retry.idempotency_key()
}

impl MemoryStore {
    fn validate_root_adapter_recording(
        &self,
        root: &ReproManifestRootV1,
        transcript_bytes: &[u8],
    ) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
        let root_input = root.as_input();
        let session = self
            .adapter_recording_sessions
            .get(&(root_input.owner_reference, root_input.run_operation_id))
            .ok_or(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
        if session.status != MemoryAdapterRecordingStatusV1::Closed
            || session.session.world_handle() != root_input.world_handle
            || session.session.admission().as_input().scope_digest
                != root_input.plugin_roster_digest
            || session.transcript_bytes.as_deref() != Some(transcript_bytes)
        {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
        let derived = memory_adapter_recording_transcript(session)
            .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
        if derived != transcript_bytes {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
        let transcript = validate_closed_adapter_recording_v1(&session.session, transcript_bytes)
            .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
        if transcript.digest() != root_input.adapter_transcript_digest {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
        Ok(())
    }

    fn check_artifact_registration_operation(
        &self,
        operation_key: (OwnerIdV1, Hash),
        root_address: Hash,
    ) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
        let operation_root = self.artifact_registration_operations.get(&operation_key);
        let mut root_operations = self
            .artifact_registration_operations
            .iter()
            .filter(|((owner_id, _), address)| {
                owner_id == &operation_key.0 && **address == root_address
            })
            .map(|((_, operation_id), _)| *operation_id);
        let root_operation = root_operations.next();
        if root_operations.next().is_some() {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
        let root_row = self.artifact_registrations.get(&root_address);

        match (operation_root, root_operation, root_row) {
            (None, None, None) => Ok(()),
            (Some(existing_root), Some(existing_operation), Some(row))
                if *existing_root == root_address
                    && existing_operation == operation_key.1
                    && row.owner_id() == &operation_key.0 =>
            {
                Ok(())
            }
            (Some(existing_root), _, _) if *existing_root != root_address => {
                Err(ArtifactRegistrationPersistenceErrorV1::Conflict)
            }
            _ => Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog),
        }
    }

    fn validate_artifact_registration_closure(
        &self,
        root: Hash,
    ) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        let mut catalog_rows = Vec::new();
        while let Some(address) = pending.pop() {
            if !seen.insert(address) {
                continue;
            }
            let row = self
                .artifact_registrations
                .get(&address)
                .ok_or(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
            let identity_key = (*row.owner_id(), row.artifact_class(), row.artifact_digest());
            if self.artifact_registration_identities.get(&identity_key) != Some(&address)
                || row.registration_address() != address
            {
                return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
            }
            catalog_rows.push(row.clone());
            pending.extend(
                row.registration()
                    .fields()
                    .child_artifacts
                    .iter()
                    .map(|edge| edge.registration_address),
            );
        }
        validate_artifact_registration_catalog_graph_v1(root, &catalog_rows)?;
        let root_row = self
            .artifact_registrations
            .get(&root)
            .ok_or(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
        if root_row.artifact_class() == ErasureArtifactClassV1::ReproManifest
            && root_row.artifact_bytes().get(2..6) == Some(b"MRM1")
        {
            let root_record =
                ReproManifestRootV1::from_canonical_cbor(root_row.artifact_bytes())
                    .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
            if self.artifact_registration_operations.get(&(
                *root_row.owner_id(),
                root_record.as_input().run_operation_id,
            )) != Some(&root)
            {
                return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
            }
            let transcript_bytes =
                find_memory_root_transcript_bytes(catalog_rows.iter(), &root_record)?;
            self.validate_root_adapter_recording(&root_record, transcript_bytes)?;
        }
        Ok(())
    }
}

fn find_memory_root_transcript_bytes<'a>(
    rows: impl Iterator<Item = &'a ArtifactRegistrationCatalogRowV1>,
    root: &ReproManifestRootV1,
) -> Result<&'a [u8], ArtifactRegistrationPersistenceErrorV1> {
    let mut transcript_bytes = None;
    for row in rows {
        if row.artifact_class() != ErasureArtifactClassV1::ReproManifest {
            continue;
        }
        let Ok(transcript) = AdapterTranscriptV1::from_canonical_cbor(row.artifact_bytes()) else {
            continue;
        };
        if transcript.digest() == root.as_input().adapter_transcript_digest
            && transcript_bytes.replace(row.artifact_bytes()).is_some()
        {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
    }
    transcript_bytes.ok_or(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
}

#[cfg(test)]
mod coverage_entrypoints {
    use super::tests::new_store;
    use super::*;
    use pos_core::{
        adapter_configuration_digest_v1, extract_adapter_admission_registration_v1,
        extract_adapter_transcript_registration_v1, extract_repro_manifest_root_registration_v1,
        prepare_artifact_registration_batch_v1, public_adapter_schema_digest_v1,
        AdapterAdmissionEntryV1, AdapterAdmissionInputV1, AdapterAdmissionV1, AdapterDataClassV1,
        AdapterEffectModeV1, AdapterInvocationInputV1, AdapterInvocationV1,
        AdapterTranscriptInputV1, ArtifactChildEdgeV1, ArtifactDataClassV1, ArtifactOptionalityV1,
        ArtifactRegistrationErrorV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationInputV1,
        ArtifactRegistrationOwnerVerificationErrorV1, ArtifactRegistrationOwnerVerifierV1,
        ArtifactRegistrationV1, ArtifactTransitionRuleV1, ReproManifestRootInputV1,
        ReproManifestRootRegistrationInputV1, WorldRecordingReceiptInputV1,
        WorldRecordingReceiptV1, WorldReplayHandleInputV1, WorldReplayHandleV1,
    };
    use pos_core::{
        ConsentAuthority, ErasureVerifiedEmptyInventoryQueryV1, ErasureVerifiedInventoryQueryV1,
        KeyIdentityV1, KeyRegistrationV1, KeyRoleV1, PublicKey, ERASURE_MAX_INVENTORY_TIMELINES,
    };

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected coverage error: {error:?}")))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_err<T: std::fmt::Debug, E: std::fmt::Debug>(value: Result<T, E>) {
        assert!(
            value.is_err(),
            "expected a rejected coverage value: {value:?}"
        );
        std::mem::drop(value);
    }

    fn draft(payload: &'static [u8]) -> EventDraft {
        EventDraft::new(
            pos_core::EntityId::new(),
            Kind::new("coverage.event"),
            pos_core::CanonicalBytes::from_static(payload),
        )
    }

    fn keyed_draft(key: u8) -> EventDraft {
        EventDraft::new(
            pos_core::EntityId::new(),
            Kind::new("coverage.event"),
            pos_core::CanonicalBytes::from_vec(vec![key]),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_recovery_receipt_digest(
        operation: ErasureReferenceV1,
        binding: ErasureReferenceV1,
        expected_generation: ErasureReferenceV1,
        child_scope: ErasureReferenceV1,
        successor_generation: ErasureReferenceV1,
        child: &TimelineMeta,
    ) -> ErasureReferenceV1 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros/erasure-fork-recovery/v1");
        hasher.update(&operation.digest());
        hasher.update(&binding.digest());
        hasher.update(&expected_generation.digest());
        hasher.update(&child_scope.digest());
        hasher.update(&successor_generation.digest());
        hasher.update(&child.id.inner().to_bytes());
        hasher.update(b"historical");
        match &child.name {
            Some(name) => {
                hasher.update(&[1]);
                hasher.update(&u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(name.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        match child.owner {
            Some(owner) => {
                hasher.update(&[1]);
                hasher.update(&owner.inner().to_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        let (parent, at_seq) = child
            .fork_point
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fork point")));
        hasher.update(&parent.inner().to_bytes());
        hasher.update(&at_seq.as_u64().to_be_bytes());
        ErasureReferenceV1::from_digest(*hasher.finalize().as_bytes())
    }

    fn identity(key: u8, scope: u8) -> AppendIdentity {
        AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([scope; 32]),
        )
    }

    fn memory_recovery_reference(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }

    fn memory_recovery_proof_cbor(
        extension: u8,
        object_reference: u8,
        manifest_bytes: &[u8],
        object_bytes: &[u8],
        state_bytes: &[u8],
        effect_reference: &ErasureReferenceV1,
        effect_bytes: &[u8],
    ) -> Vec<u8> {
        let reference = memory_recovery_reference;
        let digest_value =
            |value| ciborium::value::Value::Bytes(reference(value).digest().to_vec());
        let proof_value = ciborium::value::Value::Array(vec![
            ciborium::value::Value::Text(pos_core::ERASURE_FORK_RECOVERY_PROOF_TAG_V1.to_owned()),
            ciborium::value::Value::Integer(1.into()),
            digest_value(1),
            digest_value(2),
            digest_value(3),
            digest_value(4),
            digest_value(5),
            ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
                digest_value(1),
                digest_value(3),
                digest_value(4),
                digest_value(extension),
                digest_value(7),
                digest_value(8),
                digest_value(9),
                ciborium::value::Value::Bytes(
                    ErasureForkRecoveryProofV1::bytes_digest(manifest_bytes)
                        .digest()
                        .to_vec(),
                ),
                ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
                    digest_value(object_reference),
                    ciborium::value::Value::Bytes(
                        ErasureForkRecoveryProofV1::bytes_digest(object_bytes)
                            .digest()
                            .to_vec(),
                    ),
                ])]),
                ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
                    digest_value(11),
                    ciborium::value::Value::Bytes(
                        ErasureForkRecoveryProofV1::bytes_digest(state_bytes)
                            .digest()
                            .to_vec(),
                    ),
                ])]),
                ciborium::value::Value::Array(vec![
                    ciborium::value::Value::Array(vec![
                        ciborium::value::Value::Integer(0.into()),
                        ciborium::value::Value::Integer(0.into()),
                        digest_value(15),
                    ]),
                    ciborium::value::Value::Array(vec![
                        ciborium::value::Value::Integer(1.into()),
                        ciborium::value::Value::Integer(1.into()),
                        digest_value(16),
                    ]),
                    ciborium::value::Value::Array(vec![
                        ciborium::value::Value::Integer(2.into()),
                        ciborium::value::Value::Integer(2.into()),
                        digest_value(17),
                    ]),
                ]),
                ciborium::value::Value::Bytes(effect_reference.digest().to_vec()),
                ciborium::value::Value::Bytes(
                    ErasureForkRecoveryProofV1::bytes_digest(effect_bytes)
                        .digest()
                        .to_vec(),
                ),
                digest_value(13),
                digest_value(14),
            ])]),
        ]);
        let mut encoded = Vec::new();
        ok(ciborium::into_writer(&proof_value, &mut encoded));
        encoded
    }

    fn memory_recovery_proof_fixture(
        extension: u8,
        object_reference: u8,
    ) -> (MemoryStore, ErasureForkRecoveryProofV1) {
        let manifest_bytes = vec![0xA1, 0xB2];
        let object_bytes = vec![0xC3, 0xD4];
        let state_bytes = vec![0xE5, 0xF6];
        let reference = memory_recovery_reference;
        let effect = pos_core::ErasureCasEffectV1::ReceiptAdmission {
            receipt: reference(13),
        };
        let effect_reference = effect.identity();
        let effect_bytes = ok(effect.to_canonical_cbor());
        let encoded = memory_recovery_proof_cbor(
            extension,
            object_reference,
            &manifest_bytes,
            &object_bytes,
            &state_bytes,
            &effect_reference,
            &effect_bytes,
        );
        let proof = ok(ErasureForkRecoveryProofV1::from_canonical_cbor(&encoded));

        let mut store = new_store();
        store
            .erasure_records
            .insert(reference(7), (reference(9), manifest_bytes));
        store
            .erasure_evidence
            .insert(reference(object_reference), object_bytes);
        store.erasure_states.insert(reference(11), state_bytes);
        store
            .erasure_attempt_pages
            .insert((reference(7), 0), reference(15));
        store
            .erasure_scope_nodes
            .insert((reference(7), 1), reference(16));
        store
            .erasure_administrative_resolutions
            .insert((reference(7), 2), reference(17));
        store
            .erasure_effects
            .insert(reference(9), (effect_reference, effect_bytes));
        store
            .erasure_effect_subjects
            .insert(reference(13), reference(9));
        (store, proof)
    }

    fn assert_memory_recovery_proof_error(
        extension: u8,
        object_reference: u8,
        mutate: impl FnOnce(&mut MemoryStore),
    ) {
        assert_memory_recovery_proof_error_kind(
            ErasureErrorV1::ProvenanceMissing,
            extension,
            object_reference,
            mutate,
        );
    }

    fn assert_memory_recovery_proof_error_kind(
        expected_error: ErasureErrorV1,
        extension: u8,
        object_reference: u8,
        mutate: impl FnOnce(&mut MemoryStore),
    ) {
        let (mut store, proof) = memory_recovery_proof_fixture(extension, object_reference);
        mutate(&mut store);
        assert_eq!(
            store.memory_fork_recovery_proof_is_exact(&proof),
            Err(expected_error)
        );
    }

    fn assert_memory_recovery_proof_survives_manifest_change(
        mutate: impl FnOnce(&mut MemoryStore),
    ) {
        let (mut store, proof) = memory_recovery_proof_fixture(10, 10);
        mutate(&mut store);
        assert_eq!(store.memory_fork_recovery_proof_is_exact(&proof), Ok(()));
    }

    fn memory_recovery_proof_ignores_mutable_manifest_head() {
        assert_memory_recovery_proof_survives_manifest_change(|store| {
            store
                .erasure_records
                .remove(&ErasureReferenceV1::from_digest([7; 32]));
        });
        assert_memory_recovery_proof_survives_manifest_change(|store| {
            store.erasure_records.insert(
                ErasureReferenceV1::from_digest([7; 32]),
                (ErasureReferenceV1::from_digest([18; 32]), vec![0xA1, 0xB2]),
            );
        });
    }

    fn memory_recovery_proof_checks_objects_and_state() {
        assert_memory_recovery_proof_error(99, 10, |_| {});
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_evidence
                .remove(&ErasureReferenceV1::from_digest([10; 32]));
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_evidence
                .insert(ErasureReferenceV1::from_digest([10; 32]), vec![0xBA, 0xDB]);
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_states
                .remove(&ErasureReferenceV1::from_digest([11; 32]));
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_states
                .insert(ErasureReferenceV1::from_digest([11; 32]), vec![0xBA, 0xDB]);
        });
    }

    fn memory_recovery_proof_checks_indexes_and_effects() {
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_attempt_pages
                .remove(&(ErasureReferenceV1::from_digest([7; 32]), 0));
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store.erasure_attempt_pages.insert(
                (ErasureReferenceV1::from_digest([7; 32]), 0),
                ErasureReferenceV1::from_digest([18; 32]),
            );
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_scope_nodes
                .remove(&(ErasureReferenceV1::from_digest([7; 32]), 1));
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store.erasure_scope_nodes.insert(
                (ErasureReferenceV1::from_digest([7; 32]), 1),
                ErasureReferenceV1::from_digest([18; 32]),
            );
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_administrative_resolutions
                .remove(&(ErasureReferenceV1::from_digest([7; 32]), 2));
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store.erasure_administrative_resolutions.insert(
                (ErasureReferenceV1::from_digest([7; 32]), 2),
                ErasureReferenceV1::from_digest([18; 32]),
            );
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_effects
                .remove(&ErasureReferenceV1::from_digest([9; 32]));
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            let key = ErasureReferenceV1::from_digest([9; 32]);
            let (_, bytes) = store.erasure_effects[&key].clone();
            store
                .erasure_effects
                .insert(key, (ErasureReferenceV1::from_digest([18; 32]), bytes));
        });
        assert_memory_recovery_proof_error_kind(ErasureErrorV1::InvalidEncoding, 10, 10, |store| {
            store.erasure_effects.insert(
                ErasureReferenceV1::from_digest([9; 32]),
                (ErasureReferenceV1::from_digest([18; 32]), vec![0x17, 0x28]),
            );
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store
                .erasure_effect_subjects
                .remove(&ErasureReferenceV1::from_digest([13; 32]));
        });
        assert_memory_recovery_proof_error(10, 10, |store| {
            store.erasure_effect_subjects.insert(
                ErasureReferenceV1::from_digest([13; 32]),
                ErasureReferenceV1::from_digest([18; 32]),
            );
        });
    }

    #[test]
    fn memory_fork_recovery_proof_checks_every_persisted_side() {
        let (store, proof) = memory_recovery_proof_fixture(10, 10);
        assert_eq!(store.memory_fork_recovery_proof_is_exact(&proof), Ok(()));
        memory_recovery_proof_ignores_mutable_manifest_head();
        memory_recovery_proof_checks_objects_and_state();
        memory_recovery_proof_checks_indexes_and_effects();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_fork_recovery_rejects_missing_or_mismatched_proof() {
        let mut store = new_store();
        let parent = ok(store.create_timeline("recovery-proof-parent"));
        let snapshot =
            ok(store.complete_erasure_inventory_snapshot(ERASURE_MAX_INVENTORY_REQUESTS));
        let mut query = ErasureVerifiedEmptyInventoryQueryV1::new(snapshot);
        let inventory = ok(query.verified_inventory(ERASURE_MAX_INVENTORY_REQUESTS));
        let operation = ErasureReferenceV1::from_digest([246; 32]);
        let first_input = pos_core::ErasureForkAdmissionInputV1 {
            operation,
            expected_inventory_generation: inventory.generation(),
            child_scope: ErasureReferenceV1::from_digest([247; 32]),
            child: TimelineMeta {
                id: TimelineId::new(),
                mode: pos_core::timeline::TimelineMode::Historical,
                name: Some("recovery-proof-child".to_owned()),
                owner: None,
                fork_point: Some((parent.id(), Seq::ZERO)),
            },
        };
        let second_input = pos_core::ErasureForkAdmissionInputV1 {
            child_scope: ErasureReferenceV1::from_digest([248; 32]),
            child: TimelineMeta {
                id: TimelineId::new(),
                mode: pos_core::timeline::TimelineMode::Historical,
                name: Some("different-recovery-proof-child".to_owned()),
                owner: None,
                fork_point: Some((parent.id(), Seq::ZERO)),
            },
            ..first_input
        };
        let first = ok(inventory
            .clone()
            .prepare_fork_batch(first_input, Vec::new()));
        let stale_inventory = inventory.clone();
        let second = ok(inventory.prepare_fork_batch(second_input, Vec::new()));
        let expected = ok(first.recovery_result());
        let proof = ok(first.recovery_proof());
        let gate = Arc::clone(
            store
                .erasure_gate
                .as_ref()
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing recovery gate"))),
        );
        let candidate = first.successor_inventory().clone();
        let mut transition = |permit: &ErasureTopologyTransitionPermitV1| {
            let outcome = ok(store.commit_fork_admission(permit, first.clone()));
            Ok::<_, ErasureErrorV1>((candidate.clone(), outcome))
        };
        ok(gate.install_from_verified_inventory_transition(&mut transition));

        assert_eq!(
            ok(store.recover_fork_admission(operation, &candidate)),
            Some(expected.clone())
        );
        store.erasure_fork_recovery_proofs.remove(&operation);
        assert_eq!(
            store.recover_fork_admission(operation, &stale_inventory),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        store
            .erasure_fork_recovery_proofs
            .insert(operation, ok(second.recovery_proof()));
        assert_eq!(
            store.recover_fork_admission(operation, &stale_inventory),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        store.erasure_fork_recovery_proofs.insert(operation, proof);
        assert_eq!(
            store.recover_fork_admission(operation, &stale_inventory),
            Err(ErasureErrorV1::StaleGeneration)
        );
        assert_eq!(
            ok(store.recover_fork_admission(operation, &candidate)),
            Some(expected.clone())
        );
        fail_next_chain_hash_at_for_test();
        assert_eq!(
            store.recover_fork_admission(operation, &candidate),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        store.timelines.remove(&expected.child().id);
        assert_eq!(
            store.recover_fork_admission(operation, &candidate),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_fork_recovery_rejects_proof_without_receipt() {
        let mut store = new_store();
        let parent = ok(store.create_timeline("orphan-proof-parent"));
        let snapshot =
            ok(store.complete_erasure_inventory_snapshot(ERASURE_MAX_INVENTORY_REQUESTS));
        let mut query = ErasureVerifiedEmptyInventoryQueryV1::new(snapshot);
        let inventory = ok(query.verified_inventory(ERASURE_MAX_INVENTORY_REQUESTS));
        let operation = ErasureReferenceV1::from_digest([249; 32]);
        let admission = ok(inventory.clone().prepare_fork_batch(
            pos_core::ErasureForkAdmissionInputV1 {
                operation,
                expected_inventory_generation: inventory.generation(),
                child_scope: ErasureReferenceV1::from_digest([250; 32]),
                child: TimelineMeta {
                    id: TimelineId::new(),
                    mode: pos_core::timeline::TimelineMode::Historical,
                    name: Some("orphan-proof-child".to_owned()),
                    owner: None,
                    fork_point: Some((parent.id(), Seq::ZERO)),
                },
            },
            Vec::new(),
        ));
        let proof = ok(admission.recovery_proof());
        let expected = ok(admission.recovery_result());
        let gate = Arc::clone(
            store
                .erasure_gate
                .as_ref()
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing recovery gate"))),
        );
        let successor = admission.successor_inventory().clone();
        let mut transition = |permit: &ErasureTopologyTransitionPermitV1| {
            let outcome = ok(store.commit_fork_admission(permit, admission.clone()));
            Ok::<_, ErasureErrorV1>((successor.clone(), outcome))
        };
        ok(gate.install_from_verified_inventory_transition(&mut transition));

        assert_eq!(
            ok(store.recover_fork_admission(operation, &successor)),
            Some(expected)
        );
        store.erasure_fork_admissions.remove(&operation);
        store.erasure_fork_recovery_proofs.insert(operation, proof);
        assert_eq!(
            store.recover_fork_admission(operation, &successor),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        assert_eq!(
            store.recover_fork_admission(ErasureReferenceV1::from_digest([251; 32]), &successor),
            Ok(None)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(super) fn invalid_registry() -> KeyRegistryStateV1 {
        fn replace_first_integer(value: &mut ciborium::value::Value) -> bool {
            match value {
                ciborium::value::Value::Integer(integer)
                    if u64::try_from(*integer).ok() == Some(1) =>
                {
                    *integer = 0.into();
                    true
                }
                ciborium::value::Value::Array(values) => {
                    values.iter_mut().any(replace_first_integer)
                }
                ciborium::value::Value::Map(entries) => entries
                    .iter_mut()
                    .any(|(key, value)| replace_first_integer(key) || replace_first_integer(value)),
                ciborium::value::Value::Tag(_, value) => replace_first_integer(value),
                _ => false,
            }
        }

        let identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let mut registry = KeyRegistryStateV1::new();
        ok(registry.register_key(KeyRegistrationV1::new(
            identity,
            Hash::from_bytes([31; 32]),
            Some(PublicKey::from_bytes([32; 32])),
        )));
        let mut encoded = Vec::new();
        ok(ciborium::into_writer(&registry, &mut encoded));
        let mut value: ciborium::value::Value = ok(ciborium::from_reader(encoded.as_slice()));
        assert!(replace_first_integer(&mut value));
        let mut invalid_encoded = Vec::new();
        ok(ciborium::into_writer(&value, &mut invalid_encoded));
        ok(ciborium::from_reader(invalid_encoded.as_slice()))
    }

    #[test]
    fn memory_key_registry_revalidates_loaded_and_saved_snapshots() {
        let invalid = invalid_registry();
        let mut store = new_store();
        store.key_registry = Some(invalid.clone());
        assert!(store.load_key_registry().is_err());
        assert!(store.save_key_registry(&invalid).is_err());
        let decryption_identity =
            KeyIdentityV1::new("corrupt-owner", KeyRoleV1::SubjectDataEncryption, 1);
        let decryption_result: Result<(), KeyRegistryErrorV1> = store
            .with_decryption_authorization(
                decryption_identity,
                Hash::from_bytes([11; 32]),
                Default::default,
            );
        assert_eq!(
            decryption_result,
            Err(KeyRegistryErrorV1::RegistryUnavailable)
        );
        let identity = KeyIdentityV1::new("corrupt-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let request = pos_core::KeyDestructionRequestV1::new(
            identity,
            Hash::from_bytes([11; 32]),
            Hash::from_bytes([12; 32]),
        );
        let calls = std::cell::Cell::new(0);
        let mut callback = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            calls.set(calls.get() + 1);
            Err::<Event, _>(CoreError::Storage("callback must not run".to_owned()))
        };
        assert!(store
            .append_signed_authorized(TimelineId::new(), &invalid, &mut callback)
            .is_err());
        assert_eq!(calls.get(), 0);
        // Cover the fixture separately while asserting the store never called it.
        assert!(callback(&invalid, Seq::ZERO).is_err());
        assert!(store.begin_key_registry_destruction(request).is_err());
        assert!(store
            .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request))
            .is_err());
    }

    #[test]
    fn memory_erasure_inventory_rejects_corrupt_state_and_request_overflow() {
        let mut store = new_store();
        let state = ok(pos_core::ErasureStateV1::submitted(
            ErasureReferenceV1::from_digest([1; 32]),
            ErasureReferenceV1::from_digest([2; 32]),
            ErasureReferenceV1::from_digest([3; 32]),
        ));
        store.erasure_states.insert(
            ErasureReferenceV1::from_digest([5; 32]),
            ok(state.to_canonical_cbor()),
        );
        assert_eq!(
            store.resolve_state(ErasureReferenceV1::from_digest([5; 32])),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        store.erasure_records.insert(
            ErasureReferenceV1::from_digest([6; 32]),
            (ErasureReferenceV1::from_digest([7; 32]), Vec::new()),
        );
        store.erasure_records.insert(
            ErasureReferenceV1::from_digest([8; 32]),
            (ErasureReferenceV1::from_digest([9; 32]), Vec::new()),
        );
        assert_eq!(
            store.complete_erasure_inventory_snapshot(1),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }

    #[test]
    fn memory_erasure_inventory_rejects_topology_overflow() {
        let mut store = new_store();
        for ordinal in 0..=ERASURE_MAX_INVENTORY_TIMELINES {
            let _timeline = ok(store.create_timeline(&format!("inventory-{ordinal}")));
        }
        assert_eq!(
            store.complete_erasure_inventory_snapshot(1),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }

    #[test]
    fn memory_erasure_inventory_applies_deployment_recovery_topology_ceiling() {
        let mut store = new_store();
        let _first = ok(store.create_timeline("inventory-limits-first"));
        let _second = ok(store.create_timeline("inventory-limits-second"));
        store.erasure_records.insert(
            ErasureReferenceV1::from_digest([1; 32]),
            (ErasureReferenceV1::from_digest([2; 32]), Vec::new()),
        );
        let limits = ok(ErasureRecoveryLimitsV1::new(1, 2, 1));

        assert_eq!(
            store.complete_erasure_inventory_snapshot_with_limits(limits),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }

    #[test]
    fn memory_error_and_fork_boundaries_are_instrumented() {
        memory_error_and_fork_boundaries();
        memory_visibility_boundaries();
    }

    fn memory_error_and_fork_boundaries() {
        let mut store = new_store();
        let root = ok(store.create_timeline("coverage-root"));
        let first = ok(store.append_or_duplicate(
            root.id(),
            identity(1, 1),
            WallTime::from_micros(1),
            draft(b"first"),
        ));
        let second = ok(store.create_timeline("coverage-second"));
        let conflict = ok(store.append_or_duplicate(
            second.id(),
            identity(1, 1),
            WallTime::from_micros(1),
            draft(b"second"),
        ));
        drop((first, conflict));
        expect_err(store.revoke_owntracks_enrollment());
        expect_err(store.logical_head(pos_core::TimelineId::new()));
        expect_err(store.fork(root.id(), Seq::from_u64(2), "beyond"));
        fail_next_chain_hash_at_for_test();
        expect_err(store.fork(root.id(), Seq::ZERO, "chain-hash-failure"));
        let child = ok(store.fork(root.id(), Seq::ZERO, "child"));
        let _ = ok(store.compute_chain_hash_at(root.id(), Seq::ZERO));
        expect_err(store.compute_chain_hash_at(child.id(), Seq::from_u64(1)));

        let mut recovery_store = new_store();
        let recovery_parent = ok(recovery_store.create_timeline("recovery-parent"));
        let recovery_child =
            TimelineMeta::forked_from(recovery_parent.id(), Seq::ZERO, "recovery-child");
        let recovery_operation = ErasureReferenceV1::from_digest([241; 32]);
        let recovery_binding = ErasureReferenceV1::from_digest([242; 32]);
        let recovery_generation = ErasureReferenceV1::from_digest([243; 32]);
        let recovery_scope = ErasureReferenceV1::from_digest([244; 32]);
        let recovery_successor = ErasureReferenceV1::from_digest([245; 32]);
        let recovery_receipt = fork_recovery_receipt_digest(
            recovery_operation,
            recovery_binding,
            recovery_generation,
            recovery_scope,
            recovery_successor,
            &recovery_child,
        );
        recovery_store.erasure_fork_admissions.insert(
            recovery_operation,
            ok(ErasureForkRecoveryV1::from_persisted(
                recovery_operation,
                recovery_binding,
                recovery_generation,
                recovery_scope,
                recovery_successor,
                recovery_child,
                recovery_receipt,
            )),
        );
        let recovery_snapshot =
            ok(recovery_store.complete_erasure_inventory_snapshot(ERASURE_MAX_INVENTORY_REQUESTS));
        let mut recovery_query = ErasureVerifiedEmptyInventoryQueryV1::new(recovery_snapshot);
        let recovery_inventory =
            ok(recovery_query.verified_inventory(ERASURE_MAX_INVENTORY_REQUESTS));
        fail_next_chain_hash_at_for_test();
        assert_eq!(
            ErasureForkPersistencePortV1::recover_fork_admission(
                &mut recovery_store,
                recovery_operation,
                &recovery_inventory,
            ),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        store.test_corrupt(TestCorruption::ForkParent {
            timeline: child.id(),
            parent: pos_core::TimelineId::new(),
            fork_seq: Seq::ZERO,
        });
        expect_err(store.read(child.id(), SeqRange::all()));
        expect_err(store.read_event_by_id(child.id(), EventId::new()));

        let malformed_chain = ForkChain {
            timelines: vec![root.id(), child.id()],
            fork_seqs: Vec::new(),
        };
        expect_err(malformed_chain.segment_length(&store, 1, child.id()));
        expect_err(store.append_or_duplicate_with_limit_visible(
            TimelineId::new(),
            identity(3, 3),
            WallTime::from_micros(2),
            &draft(b"missing-visible"),
            None,
        ));
        expect_err(store.append_visible(TimelineId::new(), &[draft(b"missing-visible")]));
    }

    fn memory_visibility_boundaries() {
        let mut store = new_store();
        let protected = ok(store.create_timeline("coverage-protected"));
        ok(
            store.pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                protected.id(),
                pos_core::EntityId::new(),
                pos_core::GeoLocationAdmissionFenceV1::new(
                    1,
                    ([1; 32], 1, [2; 32]),
                    (1, false, u64::MAX - 1),
                ),
                [42; 32],
            )),
        );
        ok(store.delete_timeline(protected.id()));

        let admitted = ok(store.create_timeline("coverage-admission"));
        let admitted_entity = pos_core::EntityId::new();
        let fence =
            pos_core::GeoLocationAdmissionFenceV1::new(7, ([3; 32], 8, [4; 32]), (1, false, 1));
        ok(
            store.pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                admitted.id(),
                admitted_entity,
                fence,
                [43; 32],
            )),
        );
        store.test_remove_timeline(admitted.id());
        let request = pos_core::geo_admission::GeoLocationAdmissionRequestV1::from_input(
            pos_core::geo_admission::GeoLocationAdmissionInputV1::new(
                admitted.id(),
                admitted_entity,
                pos_core::CanonicalBytes::from_static(b"missing-state"),
                7,
                ([3; 32], 8, [4; 32]),
                (1, false, 2),
                ([5; 32], [6; 32]),
            ),
        );
        expect_err(store.admit_geo_location(request));
    }

    #[test]
    fn memory_append_and_bounded_read_boundaries_are_instrumented() {
        let mut store = new_store();
        let timeline = ok(store.create_timeline("coverage-append"));
        expect_err(store.append(pos_core::TimelineId::new(), &[draft(b"missing")]));
        let _ = ok(store.append(timeline.id(), &[draft(b"present")]));
        let bounds = EventReadBounds::new(1024, usize::MAX, usize::MAX, 1_000_000);
        let _ = ok(store.read_bounded(timeline.id(), SeqRange::all(), bounds));
        let _ = ok(store.append_bounded(timeline.id(), &[draft(b"too-many")], 1));
    }

    #[test]
    fn consent_append_rejects_a_missing_permit_after_authority_binding() {
        let mut store = new_store();
        let timeline = ok(store.create_timeline("coverage-missing-permit"));
        let authority = ConsentAuthority::new();
        ok(store.bind_consent_authority(authority.append_permit()));
        expect_err(store.append_bounded_with_boundary(timeline.id(), &[], 10, true, None, None));
    }

    #[test]
    fn consent_revocation_and_cleanup_boundaries_are_instrumented() {
        let mut store = new_store();
        let timeline = ok(store.create_timeline("coverage-revocation"));
        let subject = pos_core::EntityId::new();
        let revocation = pos_core::ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: pos_core::EntityId::new(),
            grant_seq: 1,
            fence_seq: 1,
        };
        let draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            ok(revocation.encode()),
        );
        let authority = ConsentAuthority::new();
        let permit = authority.append_permit();
        ok(store.bind_consent_authority(permit));
        let consent_scope = AppendDedupScope::from_keyed_hash([101; 32]);
        let appended = ok(store.append_consent_revocation_bounded(
            timeline.id(),
            std::slice::from_ref(&draft),
            permit,
            1,
            consent_scope,
        ));
        assert_eq!(appended.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            ok(store.pending_append_identity_cleanup()),
            Some(consent_scope)
        );
        assert_eq!(ok(store.remove_append_identities(consent_scope)), 0);
        assert_eq!(ok(store.pending_append_identity_cleanup()), None);

        let ordinary = ok(store.create_timeline("coverage-cleanup"));
        let identity_scope = AppendDedupScope::from_keyed_hash([102; 32]);
        for key in [103, 104] {
            ok(store.append_or_duplicate(
                ordinary.id(),
                AppendIdentity::new(AppendDedupKey::from_keyed_hash([key; 32]), identity_scope),
                WallTime::from_micros(1),
                keyed_draft(key),
            ));
        }
        let first =
            ok(store.remove_append_identities_bounded(identity_scope, std::num::NonZeroUsize::MIN));
        assert!(first.more_may_remain);
        assert_eq!(
            ok(store.pending_append_identity_cleanup()),
            Some(identity_scope)
        );
        let second =
            ok(store.remove_append_identities_bounded(identity_scope, std::num::NonZeroUsize::MIN));
        assert!(!second.more_may_remain);
        assert_eq!(ok(store.pending_append_identity_cleanup()), None);
    }

    #[test]
    fn memory_admin_operations_reject_geographic_timelines() {
        let mut store = new_store();
        let timeline = ok(store.create_timeline("coverage-geographic-admin"));
        store.geographic_timelines.insert(timeline.id());
        let deletion = store
            .delete_timeline(timeline.id())
            .map_err(|error| error.to_string());
        assert_eq!(
            deletion,
            Err(format!("timeline not found: {}", timeline.id()))
        );
    }

    #[test]
    fn memory_recovery_error_index_rejects_an_over_bound_read() {
        let mut store = new_store();
        let request = ErasureReferenceV1::from_digest([250_u8; 32]);
        store.test_corrupt_recovery_error_index(request, ERASURE_MAX_RECOVERY_ERRORS);
        assert_eq!(
            store.recovery_error_refs(request),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_adapter_recording_fixture(
        owner_byte: u8,
        run_byte: u8,
    ) -> Result<(AdapterRecordingSessionV1, AdapterCallReservationV1), Box<dyn std::error::Error>>
    {
        let owner_reference = Hash::from_bytes([owner_byte; 32]);
        let plugin_id = pos_core::PluginId::new();
        let configuration = b"memory-coverage-adapter".to_vec();
        let schema_digest = public_adapter_schema_digest_v1();
        let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            owner_reference,
            configuration_generation: 1,
            scope_digest: Hash::from_bytes([owner_byte.wrapping_add(1); 32]),
            entries: vec![AdapterAdmissionEntryV1 {
                plugin_id,
                adapter_id: "coverage.adapter".to_owned(),
                provider_id: "coverage.provider".to_owned(),
                operation_id: "coverage-operation".to_owned(),
                protocol_version: 1,
                request_schema_digest: schema_digest,
                response_schema_digest: schema_digest,
                configuration_digest: adapter_configuration_digest_v1(&configuration),
                exact_configuration_bytes: configuration,
                input_data_class: AdapterDataClassV1::PublicRecord,
                output_data_class: AdapterDataClassV1::PublicRecord,
                effect_mode: AdapterEffectModeV1::ReadOnly,
            }],
        })?;
        let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
            owner_reference,
            timeline_id: TimelineId::new(),
            cut_id: 1,
            commit_receipt_digest: Hash::from_bytes([owner_byte.wrapping_add(2); 32]),
            recording_receipt_digest: Hash::from_bytes([owner_byte.wrapping_add(3); 32]),
            logical_head: 0,
            stitched_head_hash: Hash::from_bytes([owner_byte.wrapping_add(4); 32]),
        })?;
        let run_operation_id = Hash::from_bytes([run_byte; 32]);
        let session = AdapterRecordingSessionV1::new(
            owner_reference,
            world_handle,
            run_operation_id,
            admission,
        )?;
        let invocation = AdapterInvocationV1::new(AdapterInvocationInputV1 {
            adapter_id: "coverage.adapter".to_owned(),
            provider_id: "coverage.provider".to_owned(),
            operation_id: "coverage-operation".to_owned(),
            protocol_version: 1,
            request_schema_digest: schema_digest,
            response_schema_digest: schema_digest,
            configuration_digest: adapter_configuration_digest_v1(b"memory-coverage-adapter"),
            global_call_index: 0,
            exact_request_payload: b"coverage request".to_vec(),
        })?;
        let reservation = AdapterCallReservationV1::new(
            plugin_id,
            0,
            invocation,
            Hash::from_bytes([owner_byte.wrapping_add(5); 32]),
            1,
        )?;
        Ok((session, reservation))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn closed_memory_adapter_recording(
        run_byte: u8,
    ) -> Result<(MemoryStore, AdapterRecordingSessionV1), Box<dyn std::error::Error>> {
        let (session, reservation) = memory_adapter_recording_fixture(180, run_byte)?;
        let owner_reference = session.owner_reference();
        let run_operation_id = session.run_operation_id();
        let mut store = MemoryStore::new();
        store.open_adapter_recording_session(session.clone())?;
        store.reserve_adapter_call(owner_reference, run_operation_id, reservation)?;
        store.complete_adapter_call(
            owner_reference,
            run_operation_id,
            0,
            b"coverage response".to_vec(),
        )?;
        store.close_adapter_recording_session(owner_reference, run_operation_id)?;
        Ok((store, session))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_adapter_recording_rejects_retained_corruption(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut store, session) = closed_memory_adapter_recording(181)?;
        let owner_reference = session.owner_reference();
        let run_operation_id = session.run_operation_id();
        {
            let journal = store
                .adapter_recording_sessions
                .get_mut(&(owner_reference, run_operation_id))
                .ok_or("missing closed memory recorder")?;
            journal.transcript_bytes = None;
        }
        assert_eq!(
            store.close_adapter_recording_session(owner_reference, run_operation_id),
            Err(AdapterRecordingStoreErrorV1::CorruptState)
        );
        assert_eq!(
            store.read_closed_adapter_recording_session(owner_reference, run_operation_id),
            Err(AdapterRecordingStoreErrorV1::CorruptState)
        );

        let (mut store, session) = closed_memory_adapter_recording(182)?;
        let owner_reference = session.owner_reference();
        let run_operation_id = session.run_operation_id();
        {
            let journal = store
                .adapter_recording_sessions
                .get_mut(&(owner_reference, run_operation_id))
                .ok_or("missing closed memory recorder")?;
            journal.transcript_bytes = Some(b"changed retained transcript".to_vec());
        }
        assert_eq!(
            store.close_adapter_recording_session(owner_reference, run_operation_id),
            Err(AdapterRecordingStoreErrorV1::CorruptState)
        );

        let (mut store, session) = closed_memory_adapter_recording(183)?;
        let owner_reference = session.owner_reference();
        let run_operation_id = session.run_operation_id();
        {
            let journal = store
                .adapter_recording_sessions
                .get_mut(&(owner_reference, run_operation_id))
                .ok_or("missing closed memory recorder")?;
            journal.calls.clear();
        }
        assert_eq!(
            store.read_closed_adapter_recording_session(owner_reference, run_operation_id),
            Err(AdapterRecordingStoreErrorV1::CorruptState)
        );

        let (mut store, session) = closed_memory_adapter_recording(184)?;
        let owner_reference = session.owner_reference();
        let run_operation_id = session.run_operation_id();
        {
            let journal = store
                .adapter_recording_sessions
                .get_mut(&(owner_reference, run_operation_id))
                .ok_or("missing closed memory recorder")?;
            journal
                .calls
                .get_mut(&0)
                .ok_or("missing memory recorder call")?
                .output_bytes = None;
        }
        assert_eq!(
            store.read_closed_adapter_recording_session(owner_reference, run_operation_id),
            Err(AdapterRecordingStoreErrorV1::InvalidState)
        );
        assert_eq!(
            store.close_adapter_recording_session(owner_reference, run_operation_id),
            Err(AdapterRecordingStoreErrorV1::InvalidState)
        );

        let (mut store, session) = closed_memory_adapter_recording(185)?;
        let owner_reference = session.owner_reference();
        let run_operation_id = session.run_operation_id();
        let (wrong_session, _) = memory_adapter_recording_fixture(186, 185)?;
        {
            let journal = store
                .adapter_recording_sessions
                .get_mut(&(owner_reference, run_operation_id))
                .ok_or("missing closed memory recorder")?;
            journal.session = wrong_session;
        }
        assert_eq!(
            store.read_closed_adapter_recording_session(owner_reference, run_operation_id),
            Err(AdapterRecordingStoreErrorV1::CorruptState)
        );
        Ok(())
    }

    type CatalogFixture = (
        PreparedArtifactRegistrationBatchV1,
        AdapterRecordingSessionV1,
    );
    type CommittedCatalog = (
        MemoryStore,
        PreparedArtifactRegistrationBatchV1,
        (Hash, Hash),
    );

    // This fixture isolates the memory catalog port. Its synthetic WCR1
    // registration is not Wave 8 owner-verification evidence.
    struct MemoryCatalogOwnerVerifier;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl ArtifactRegistrationOwnerVerifierV1 for MemoryCatalogOwnerVerifier {
        fn derive_native_registration(
            &self,
            owner_id: &OwnerIdV1,
            artifact_class: ErasureArtifactClassV1,
            artifact_bytes: &[u8],
        ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1> {
            structural_registration(owner_id, artifact_class, artifact_bytes, Vec::new())
                .map_err(|_| ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
        }

        fn verify_committed_artifact(
            &self,
            _owner_id: &OwnerIdV1,
            _artifact_bytes: &[u8],
            _registration: &ArtifactRegistrationV1,
        ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1> {
            Ok(())
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn structural_registration(
        owner_id: &OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
        child_artifacts: Vec<ArtifactChildEdgeV1>,
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationErrorV1> {
        ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
            artifact_class,
            artifact_digest: ArtifactRegistrationV1::artifact_digest(
                artifact_class,
                artifact_bytes,
            ),
            owner_reference: ArtifactRegistrationV1::owner_reference(owner_id),
            data_class: ArtifactDataClassV1::StructuralAuditMetadata,
            optionality: ArtifactOptionalityV1::Required,
            transition_rule: ArtifactTransitionRuleV1::PreserveExact,
            required_key_roles: Vec::new(),
            key_dependencies: Vec::new(),
            child_artifacts,
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn catalog_row(
        owner_id: OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
        child_artifacts: Vec<ArtifactChildEdgeV1>,
    ) -> Result<ArtifactRegistrationCatalogRowV1, Box<dyn std::error::Error>> {
        let registration =
            structural_registration(&owner_id, artifact_class, artifact_bytes, child_artifacts)?;
        let row = ArtifactRegistrationCatalogRowV1::from_persisted(
            owner_id,
            artifact_class,
            registration.fields().artifact_digest,
            registration.address(),
            artifact_bytes.to_vec(),
            registration.canonical_cbor(),
        )?;
        Ok(row)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn child_edge(row: &ArtifactRegistrationCatalogRowV1) -> ArtifactChildEdgeV1 {
        ArtifactChildEdgeV1 {
            artifact_class: row.artifact_class(),
            artifact_digest: row.artifact_digest(),
            registration_address: row.registration_address(),
            required: true,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn insert_catalog_row(store: &mut MemoryStore, row: ArtifactRegistrationCatalogRowV1) {
        let address = row.registration_address();
        let identity = (*row.owner_id(), row.artifact_class(), row.artifact_digest());
        store
            .artifact_registration_identities
            .insert(identity, address);
        store.artifact_registrations.insert(address, row);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn commit_catalog(
        store: &mut MemoryStore,
        batch: PreparedArtifactRegistrationBatchV1,
    ) -> Result<ArtifactRegistrationCommitOutcomeV1, ArtifactRegistrationPersistenceErrorV1> {
        ArtifactRegistrationPersistencePortV1::commit_artifact_registration_batch(store, batch)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_catalog_error(
        store: &MemoryStore,
        owner: &OwnerIdV1,
        address: Hash,
    ) -> Option<ArtifactRegistrationPersistenceErrorV1> {
        ArtifactRegistrationPersistencePortV1::read_artifact_registration(store, owner, address)
            .err()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_catalog_batch() -> Result<CatalogFixture, Box<dyn std::error::Error>> {
        let owner_id = OwnerIdV1::from_static("memory-coverage-catalog");
        let owner_reference = ArtifactRegistrationV1::owner_reference(&owner_id);
        let operation_id = Hash::from_bytes([0x61; 32]);
        let commit_receipt_digest = Hash::from_bytes([0x62; 32]);
        let recording = WorldRecordingReceiptV1::new(WorldRecordingReceiptInputV1 {
            binding_hash: Hash::from_bytes([0x63; 32]),
            operation_id,
            actual_commit_receipt_digest: commit_receipt_digest,
            installed_inventory_generation: Hash::from_bytes([0x64; 32]),
        })?;
        let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
            owner_reference,
            timeline_id: TimelineId::new(),
            cut_id: 2,
            commit_receipt_digest,
            recording_receipt_digest: recording.digest(),
            logical_head: 0,
            stitched_head_hash: Hash::from_bytes([0x65; 32]),
        })?;
        let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            owner_reference,
            configuration_generation: 1,
            scope_digest: Hash::from_bytes([0x66; 32]),
            entries: Vec::new(),
        })?;
        let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
            owner_reference,
            world_handle,
            run_operation_id: operation_id,
            adapter_admission_digest: admission.digest(),
            calls: Vec::new(),
        })?;
        let root = ReproManifestRootV1::new(ReproManifestRootInputV1 {
            owner_reference,
            world_handle,
            run_operation_id: operation_id,
            plugin_roster_digest: admission.as_input().scope_digest,
            adapter_transcript_digest: transcript.digest(),
            created_at_micros: 2,
            label: None,
        })?;
        let session = AdapterRecordingSessionV1::new(
            owner_reference,
            world_handle,
            operation_id,
            admission.clone(),
        )?;
        let admission_bytes = admission.to_canonical_cbor();
        let transcript_bytes = transcript.to_canonical_cbor();
        let recording_bytes = recording.to_canonical_cbor();
        let root_bytes = root.to_canonical_cbor();
        let admission_registration = extract_adapter_admission_registration_v1(&admission_bytes)?;
        let transcript_registration = extract_adapter_transcript_registration_v1(
            &transcript_bytes,
            &admission_bytes,
            &admission_registration,
        )?;
        let recording_registration = structural_registration(
            &owner_id,
            ErasureArtifactClassV1::TimelineReplay,
            &recording_bytes,
            Vec::new(),
        )?;
        let root_registration =
            extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
                root_bytes: &root_bytes,
                recording_receipt_bytes: &recording_bytes,
                recording_registration: &recording_registration,
                transcript_bytes: &transcript_bytes,
                admission_bytes: &admission_bytes,
                admission_registration: &admission_registration,
                transcript_registration: &transcript_registration,
                owner_id: &owner_id,
                label_data_class: None,
            })?;
        let root_address = root_registration.address();
        let inputs = [
            (admission_bytes, admission_registration),
            (transcript_bytes, transcript_registration),
            (recording_bytes, recording_registration),
            (root_bytes, root_registration),
        ]
        .into_iter()
        .map(
            |(artifact_bytes, registration)| ArtifactRegistrationInputV1 {
                owner_id,
                artifact_bytes,
                registration_cbor: registration.canonical_cbor().to_vec(),
            },
        )
        .collect();
        let batch = prepare_artifact_registration_batch_v1(
            owner_id,
            root_address,
            inputs,
            &MemoryCatalogOwnerVerifier,
        )?;
        Ok((batch, session))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn committed_memory_catalog() -> Result<CommittedCatalog, Box<dyn std::error::Error>> {
        let (batch, session) = memory_catalog_batch()?;
        let key = (session.owner_reference(), session.run_operation_id());
        let mut store = MemoryStore::new();
        store.open_adapter_recording_session(session)?;
        store.close_adapter_recording_session(key.0, key.1)?;
        assert_eq!(
            commit_catalog(&mut store, batch.clone())?,
            ArtifactRegistrationCommitOutcomeV1::Applied
        );
        Ok((store, batch, key))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_catalog_commit_rejects_corrupt_retained_indexes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut store, batch, _) = committed_memory_catalog()?;
        store.artifact_registration_identities.clear();
        assert_eq!(
            commit_catalog(&mut store, batch),
            Err(ArtifactRegistrationPersistenceErrorV1::Conflict)
        );

        let (mut store, batch, _) = committed_memory_catalog()?;
        let owner = *batch.owner_id();
        let root = batch.root_registration_address();
        store.artifact_registration_operations.clear();
        assert_eq!(
            read_catalog_error(&store, &owner, root),
            Some(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        assert_eq!(
            commit_catalog(&mut store, batch),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );

        let (mut store, batch, _) = committed_memory_catalog()?;
        let second_operation = (*batch.owner_id(), Hash::from_bytes([0x6f; 32]));
        store
            .artifact_registration_operations
            .insert(second_operation, batch.root_registration_address());
        assert_eq!(
            commit_catalog(&mut store, batch),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_catalog_read_rejects_corrupt_retained_rows_and_indexes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut store, batch, _) = committed_memory_catalog()?;
        let owner = *batch.owner_id();
        let root = batch.root_registration_address();
        store.artifact_registrations.remove(&root);
        assert_eq!(
            read_catalog_error(&store, &owner, root),
            Some(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );

        let (mut store, batch, _) = committed_memory_catalog()?;
        let root = batch.root_registration_address();
        store
            .artifact_registrations
            .retain(|address, _| *address == root);
        assert_eq!(
            read_catalog_error(&store, &owner, root),
            Some(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );

        let (mut store, batch, _) = committed_memory_catalog()?;
        let root = batch.root_registration_address();
        store
            .artifact_registration_identities
            .retain(|_, address| *address == root);
        assert_eq!(
            read_catalog_error(&store, &owner, root),
            Some(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );

        let (mut store, batch, key) = committed_memory_catalog()?;
        let root = batch.root_registration_address();
        store
            .adapter_recording_sessions
            .get_mut(&key)
            .ok_or("missing memory catalog recorder")?
            .status = MemoryAdapterRecordingStatusV1::Open;
        assert_eq!(
            read_catalog_error(&store, &owner, root),
            Some(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        assert_eq!(
            commit_catalog(&mut store, batch),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_catalog_commit_rejects_a_recorder_that_no_longer_derives_the_root(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_, reservation) = memory_adapter_recording_fixture(190, 191)?;
        let pending = MemoryAdapterRecordingCallV1 {
            reservation,
            output_bytes: None,
        };
        let (mut store, batch, key) = committed_memory_catalog()?;
        store
            .adapter_recording_sessions
            .get_mut(&key)
            .ok_or("missing memory catalog recorder")?
            .calls
            .insert(0, pending);
        assert_eq!(
            commit_catalog(&mut store, batch),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );

        let (mut store, batch, key) = committed_memory_catalog()?;
        let journal = store
            .adapter_recording_sessions
            .get_mut(&key)
            .ok_or("missing memory catalog recorder")?;
        journal.session = AdapterRecordingSessionV1::new(
            journal.session.owner_reference(),
            journal.session.world_handle(),
            Hash::from_bytes([0x6e; 32]),
            journal.session.admission().clone(),
        )?;
        assert_eq!(
            commit_catalog(&mut store, batch),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_catalog_read_revalidates_shared_children_and_native_rows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let owner = OwnerIdV1::from_static("memory-coverage-graph");
        let class = ErasureArtifactClassV1::TimelineReplay;
        let leaf = catalog_row(owner, class, b"shared leaf", Vec::new())?;
        let middle = catalog_row(owner, class, b"middle", vec![child_edge(&leaf)])?;
        let mut root_children = vec![child_edge(&middle), child_edge(&leaf)];
        root_children.sort_by_key(|edge| edge.artifact_digest);
        let root = catalog_row(owner, class, b"diamond root", root_children)?;
        let mut store = MemoryStore::new();
        for row in [leaf, middle, root.clone()] {
            insert_catalog_row(&mut store, row);
        }
        let read = ArtifactRegistrationPersistencePortV1::read_artifact_registration(
            &store,
            &owner,
            root.registration_address(),
        )?;
        assert_eq!(read, Some(root));

        let native = catalog_row(
            owner,
            ErasureArtifactClassV1::ReproManifest,
            b"not a native manifest",
            Vec::new(),
        )?;
        let native_address = native.registration_address();
        insert_catalog_row(&mut store, native);
        assert_eq!(
            read_catalog_error(&store, &owner, native_address),
            Some(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_catalog_root_lookup_rejects_a_duplicated_transcript_row(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (store, batch, _) = committed_memory_catalog()?;
        let rows: Vec<_> = store.artifact_registrations.values().collect();
        let root_row = rows
            .iter()
            .find(|row| row.registration_address() == batch.root_registration_address())
            .ok_or("missing memory catalog root")?;
        let root = ReproManifestRootV1::from_canonical_cbor(root_row.artifact_bytes())?;
        assert_eq!(
            find_memory_root_transcript_bytes(rows.iter().chain(rows.iter()).copied(), &root),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_adapter_reservation_requires_the_next_plugin_ordinal(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (session, reservation) = memory_adapter_recording_fixture(192, 193)?;
        let owner_reference = session.owner_reference();
        let run_operation_id = session.run_operation_id();
        let mut store = MemoryStore::new();
        store.open_adapter_recording_session(session)?;
        store.reserve_adapter_call(owner_reference, run_operation_id, reservation.clone())?;
        let invocation = AdapterInvocationV1::new(AdapterInvocationInputV1 {
            global_call_index: 1,
            ..reservation.invocation().as_input().clone()
        })?;
        let repeated_ordinal = AdapterCallReservationV1::new(
            reservation.plugin_id(),
            0,
            invocation.clone(),
            Hash::from_bytes([0x6d; 32]),
            2,
        )?;
        assert_eq!(
            store.reserve_adapter_call(owner_reference, run_operation_id, repeated_ordinal),
            Err(AdapterRecordingStoreErrorV1::InvalidCall)
        );
        let next_ordinal = AdapterCallReservationV1::new(
            reservation.plugin_id(),
            1,
            invocation,
            Hash::from_bytes([0x6c; 32]),
            2,
        )?;
        let expected = AdapterCallReservationOutcomeV1::Reserved {
            reserved_at_micros: 2,
        };
        assert_eq!(
            store.reserve_adapter_call(owner_reference, run_operation_id, next_ordinal),
            Ok(expected)
        );
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod manifest_owner_admission_coverage {
    use super::*;
    use crate::manifest_owner_fixtures::{
        catalog, hash, plugin, policy_copies, AcceptingOwner, PolicySource,
    };
    use pos_core::{
        prepare_manifest_owner_admission_v1, ManifestOwnerAdmissionRequestV1,
        ManifestOwnerTimelineAdmissionRequestV1, WorldConsumerSetInputV1, WorldConsumerSetV1,
        WorldConsumerV1, WorldProducerV1,
    };

    type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
    type TestResult = FixtureResult<()>;
    type Corruption = fn(&mut MemoryStore) -> TestResult;

    const OWNER: [u8; 32] = [0x4d; 32];
    const CORRUPT_STATE: Result<(), ManifestOwnerAdmissionErrorV1> =
        Err(ManifestOwnerAdmissionErrorV1::CorruptState);

    const fn owned_timeline(byte: u8) -> TimelineId {
        TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
    }

    fn timeline_request(
        index: usize,
        timeline_id: TimelineId,
        sources: &[PolicySource],
    ) -> FixtureResult<ManifestOwnerTimelineAdmissionRequestV1> {
        let offset = u8::try_from(index).unwrap_or(u8::MAX);
        let scope = hash(70 + offset);
        let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope,
            consumers: vec![WorldConsumerV1::new(
                "local-observer".to_owned(),
                hash(130),
                hash(131),
                hash(132),
            )?],
            producers: vec![WorldProducerV1::new(plugin(1), sources[0].0.digest())?],
            optional_view_roots: Vec::new(),
        })?;
        Ok(ManifestOwnerTimelineAdmissionRequestV1 {
            timeline_id,
            scope,
            wcs1,
            policy_copies: policy_copies(OWNER, scope, sources, hash(80 + offset))?,
        })
    }

    /// Prepare the successor of `current` (or genesis) owning `timeline_ids`.
    fn prepared(
        current: Option<&ManifestOwnerAdmissionOwnerStateV1>,
        timeline_ids: &[TimelineId],
    ) -> FixtureResult<PreparedManifestOwnerAdmissionV1> {
        let generation = current.map_or(1, |state| state.configuration_generation + 1);
        let seed = u8::try_from(generation).unwrap_or(u8::MAX);
        let (catalog, sources) = catalog(OWNER, generation)?;
        let timelines = timeline_ids
            .iter()
            .enumerate()
            .map(|(index, timeline_id)| timeline_request(index, *timeline_id, &sources))
            .collect::<FixtureResult<Vec<_>>>()?;
        let request = ManifestOwnerAdmissionRequestV1 {
            operation_id: hash(40 + seed),
            catalog,
            expected_configuration_generation: current.map(|state| state.configuration_generation),
            previous_visible_lcq1_hash: current.and_then(|state| state.previous_visible_lcq1_hash),
            expected_inventory_generation: current.map(|state| state.inventory_generation),
            resulting_inventory_generation: hash(50 + seed),
            timelines,
        };
        let batch = prepare_manifest_owner_admission_v1(request, &AcceptingOwner, current)?;
        Ok(batch)
    }

    const fn genesis_timelines() -> [TimelineId; 2] {
        [owned_timeline(1), owned_timeline(2)]
    }

    /// Store holding generation 1 (operation `hash(41)`, Timelines 1 and 2).
    fn genesis_store() -> FixtureResult<MemoryStore> {
        let mut store = MemoryStore::new();
        store.commit_manifest_owner_admission_v1(prepared(None, &genesis_timelines())?)?;
        Ok(store)
    }

    /// Store holding generation 1 and its replacement generation 2
    /// (operation `hash(42)`, Timelines 3 and 4).
    fn replaced_store() -> FixtureResult<MemoryStore> {
        let mut store = genesis_store()?;
        let current = store
            .read_manifest_owner_state_v1(OWNER)?
            .ok_or("missing genesis owner state")?;
        let replacement = prepared(Some(&current), &[owned_timeline(3), owned_timeline(4)])?;
        store.commit_manifest_owner_admission_v1(replacement)?;
        Ok(store)
    }

    fn genesis_with(corrupt: Corruption) -> FixtureResult<MemoryStore> {
        let mut store = genesis_store()?;
        corrupt(&mut store)?;
        Ok(store)
    }

    fn state_mut(
        store: &mut MemoryStore,
    ) -> FixtureResult<&mut MemoryManifestOwnerAdmissionStateV1> {
        store
            .manifest_owner_admission_states
            .get_mut(&OWNER)
            .ok_or_else(|| "missing owner state".into())
    }

    fn operation_mut(
        store: &mut MemoryStore,
        operation_id: Hash,
    ) -> FixtureResult<&mut MemoryManifestOwnerAdmissionOperationV1> {
        store
            .manifest_owner_admission_operations
            .get_mut(&(OWNER, operation_id))
            .ok_or_else(|| "missing owner operation".into())
    }

    fn snapshot_mut(
        store: &mut MemoryStore,
        generation: u64,
        timeline_id: TimelineId,
    ) -> FixtureResult<&mut ManifestOwnerAdmissionSnapshotV1> {
        store
            .manifest_owner_admission_snapshots
            .get_mut(&(OWNER, generation, timeline_id))
            .ok_or_else(|| "missing owner snapshot".into())
    }

    fn drop_state(store: &mut MemoryStore) -> TestResult {
        store
            .manifest_owner_admission_states
            .remove(&OWNER)
            .ok_or("missing owner state")?;
        Ok(())
    }

    fn drop_operation(store: &mut MemoryStore, operation_id: Hash) -> TestResult {
        store
            .manifest_owner_admission_operations
            .remove(&(OWNER, operation_id))
            .ok_or("missing owner operation")?;
        Ok(())
    }

    fn insert_operation(
        store: &mut MemoryStore,
        operation_id: Hash,
        operation: MemoryManifestOwnerAdmissionOperationV1,
    ) {
        store
            .manifest_owner_admission_operations
            .insert((OWNER, operation_id), operation);
    }

    fn drop_snapshot(
        store: &mut MemoryStore,
        generation: u64,
        timeline_id: TimelineId,
    ) -> TestResult {
        store
            .manifest_owner_admission_snapshots
            .remove(&(OWNER, generation, timeline_id))
            .ok_or("missing owner snapshot")?;
        Ok(())
    }

    fn insert_snapshot(
        store: &mut MemoryStore,
        generation: u64,
        timeline_id: TimelineId,
        snapshot: ManifestOwnerAdmissionSnapshotV1,
    ) {
        store
            .manifest_owner_admission_snapshots
            .insert((OWNER, generation, timeline_id), snapshot);
    }

    fn clear_snapshots(store: &mut MemoryStore) {
        store.manifest_owner_admission_snapshots.clear();
    }

    fn intent(store: &MemoryStore, operation_id: Hash) -> FixtureResult<Hash> {
        store
            .manifest_owner_admission_operations
            .get(&(OWNER, operation_id))
            .map(|operation| operation.intent_digest)
            .ok_or_else(|| "missing owner operation".into())
    }

    #[test]
    fn owner_rows_without_a_state_row_are_corrupt() -> TestResult {
        let mut store = genesis_store()?;
        assert_eq!(store.read_manifest_owner_state_v1([0x4e; 32]), Ok(None));

        drop_state(&mut store)?;
        assert_eq!(
            store.read_manifest_owner_state_v1(OWNER).map(drop),
            CORRUPT_STATE
        );

        clear_snapshots(&mut store);
        assert_eq!(
            store.read_manifest_owner_state_v1(OWNER).map(drop),
            CORRUPT_STATE
        );
        let genesis_intent = intent(&store, hash(41))?;
        assert_eq!(
            store
                .resolve_manifest_owner_admission_retry_v1(OWNER, hash(41), genesis_intent)
                .map(drop),
            CORRUPT_STATE
        );
        let retry = prepared(None, &genesis_timelines())?;
        assert_eq!(
            store.commit_manifest_owner_admission_v1(retry).map(drop),
            CORRUPT_STATE
        );
        Ok(())
    }

    #[test]
    fn current_owner_state_rejects_each_inconsistent_retained_row() -> TestResult {
        let corruptions: [Corruption; 6] = [
            |store| {
                state_mut(store)?.timelines.clear();
                Ok(())
            },
            |store| {
                state_mut(store)?.timelines.insert(owned_timeline(9));
                Ok(())
            },
            |store| {
                let state = state_mut(store)?;
                state.timelines.remove(&owned_timeline(2));
                state.timelines.insert(owned_timeline(9));
                Ok(())
            },
            |store| {
                state_mut(store)?.inventory_generation = hash(99);
                Ok(())
            },
            |store| drop_operation(store, hash(41)),
            |store| {
                operation_mut(store, hash(41))?.result.kind =
                    ManifestOwnerAdmissionCommitKindV1::ExactRetry;
                Ok(())
            },
        ];
        for corrupt in corruptions {
            let store = genesis_with(corrupt)?;
            assert_eq!(
                store.read_manifest_owner_state_v1(OWNER).map(drop),
                CORRUPT_STATE
            );
        }
        Ok(())
    }

    #[test]
    fn retry_resolves_and_rejects_historical_generation_rows() -> TestResult {
        let store = replaced_store()?;
        for operation_id in [hash(41), hash(42)] {
            let retry = store
                .resolve_manifest_owner_admission_retry_v1(
                    OWNER,
                    operation_id,
                    intent(&store, operation_id)?,
                )?
                .ok_or("missing exact retry")?;
            assert_eq!(retry.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
        }

        let corruptions: [Corruption; 3] = [
            |store| {
                operation_mut(store, hash(41))?
                    .result
                    .receipt_hashes
                    .clear();
                Ok(())
            },
            |store| {
                snapshot_mut(store, 1, owned_timeline(1))?.resulting_inventory_generation =
                    hash(99);
                Ok(())
            },
            |store| drop_snapshot(store, 1, owned_timeline(2)),
        ];
        for corrupt in corruptions {
            let mut damaged_store = replaced_store()?;
            corrupt(&mut damaged_store)?;
            let genesis_intent = intent(&damaged_store, hash(41))?;
            assert_eq!(
                damaged_store
                    .resolve_manifest_owner_admission_retry_v1(OWNER, hash(41), genesis_intent)
                    .map(drop),
                CORRUPT_STATE
            );
        }
        Ok(())
    }

    #[test]
    fn commit_rejects_an_occupied_successor_generation_row() -> TestResult {
        let mut store = genesis_store()?;
        let current = store
            .read_manifest_owner_state_v1(OWNER)?
            .ok_or("missing genesis owner state")?;
        let stray = snapshot_mut(&mut store, 1, owned_timeline(1))?.clone();
        insert_snapshot(&mut store, 2, owned_timeline(3), stray);
        let replacement = prepared(Some(&current), &[owned_timeline(3), owned_timeline(4)])?;
        assert_eq!(
            store.commit_manifest_owner_admission_v1(replacement),
            Err(ManifestOwnerAdmissionErrorV1::Conflict)
        );
        Ok(())
    }

    #[test]
    fn historical_read_rejects_each_inconsistent_generation_row() -> TestResult {
        let store = genesis_store()?;
        assert_eq!(
            store.read_manifest_owner_admission_v1(OWNER, 3, owned_timeline(1)),
            Ok(None)
        );

        let corruptions: [Corruption; 6] = [
            |store| {
                snapshot_mut(store, 1, owned_timeline(1))?.resulting_inventory_generation =
                    Hash::zero();
                Ok(())
            },
            |store| drop_operation(store, hash(41)),
            |store| {
                operation_mut(store, hash(41))?.result.inventory_generation = hash(99);
                Ok(())
            },
            |store| {
                let duplicate = operation_mut(store, hash(41))?.clone();
                insert_operation(store, hash(77), duplicate);
                Ok(())
            },
            |store| {
                snapshot_mut(store, 1, owned_timeline(2))?.resulting_inventory_generation =
                    hash(99);
                Ok(())
            },
            |store| {
                operation_mut(store, hash(41))?
                    .result
                    .receipt_hashes
                    .reverse();
                Ok(())
            },
        ];
        for corrupt in corruptions {
            let store = genesis_with(corrupt)?;
            assert_eq!(
                store
                    .read_manifest_owner_admission_v1(OWNER, 1, owned_timeline(1))
                    .map(drop),
                CORRUPT_STATE
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod local_cut_owner_coverage {
    use super::*;
    use pos_core::{
        output_policy::{OutputPolicyInputV1, OutputPolicyV1},
        prepare_local_cut_owner_commit_v1, prepare_manifest_owner_admission_v1,
        ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, LocalCutCommitV1,
        LocalCutCompositionBindingRowV1, LocalCutManifestBindingRowV1,
        LocalCutManifestBindingTableV1, LocalCutOwnerVerifierV1, LocalCutReceiptInputV1,
        LocalCutReceiptV1, LocalCutRecordingContextRowV1, LocalCutSealInputV2, LocalCutSealV2,
        LocalCutTableRefV1, ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1,
        ManifestAdmissionCatalogV1, ManifestOwnerAdmissionRequestV1,
        ManifestOwnerAdmissionVerifierV1, ManifestOwnerPolicyCopiesV1,
        ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
        ManifestSlotAdmissionReceiptV1, PluginId, WorldArtifactKindV1, WorldArtifactLeafInputV1,
        WorldArtifactLeafV1, WorldConsumerSetInputV1, WorldConsumerSetV1, WorldConsumerV1,
        WorldProducerV1,
    };

    type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
    type TestResult = FixtureResult<()>;
    type PolicySource = (OutputPolicyV1, Vec<u8>);

    const CUT_OWNER: [u8; 32] = [0x41; 32];
    const IDLE_OWNER: [u8; 32] = [0x42; 32];
    const PEER_OWNER: [u8; 32] = [0x43; 32];
    const STRANGER: [u8; 32] = [0x44; 32];
    const CUT_TIMELINE: TimelineId = timeline(1);
    const NEXT_TIMELINE: TimelineId = timeline(2);
    const IDLE_TIMELINE: TimelineId = timeline(3);
    const PEER_TIMELINE: TimelineId = timeline(4);
    const CUT_ROSTER: [([u8; 32], TimelineId); 1] = [(CUT_OWNER, CUT_TIMELINE)];
    const ADMISSION_OPERATION: Hash = hash(0x51);
    const EVIDENCE: Hash = hash(90);
    const SIGNATURE: [u8; 64] = [0x5a; 64];
    const FIRST_CUT: CutPlan = CutPlan {
        cut_id: 1,
        tick: 1,
        membership_epoch: 0,
        operation_id: hash(0x61),
        result_inventory: hash(0x71),
    };
    const SECOND_CUT: CutPlan = CutPlan {
        cut_id: 2,
        tick: 2,
        membership_epoch: 0,
        operation_id: hash(0x62),
        result_inventory: hash(0x72),
    };
    const RIVAL_CUT: CutPlan = CutPlan {
        cut_id: 1,
        tick: 1,
        membership_epoch: 0,
        operation_id: hash(0x63),
        result_inventory: hash(0x73),
    };
    const EPOCH_CUT: CutPlan = CutPlan {
        cut_id: 1,
        tick: 1,
        membership_epoch: 3,
        operation_id: hash(0x64),
        result_inventory: hash(0x74),
    };

    struct CutPlan {
        cut_id: u64,
        tick: u64,
        membership_epoch: u32,
        operation_id: Hash,
        result_inventory: Hash,
    }

    struct AdmittedView {
        state: ManifestOwnerAdmissionOwnerStateV1,
        snapshots: Vec<ManifestOwnerAdmissionSnapshotV1>,
    }

    struct AcceptingOwner;

    impl ManifestOwnerAdmissionVerifierV1 for AcceptingOwner {
        fn verify_complete_composition(
            &self,
            _catalog: &ManifestAdmissionCatalogV1,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn verify_complete_owned_scope_set(
            &self,
            _owner_id: [u8; 32],
            _timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn verify_coordinator_receipt(
            &self,
            _receipt: &ManifestSlotAdmissionReceiptV1,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn verify_owner_prestate_and_allocation(
            &self,
            _request: &ManifestOwnerAdmissionRequestV1,
            _current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }

        fn sign_coordinator_receipt(
            &self,
            draft: ManifestSlotAdmissionReceiptDraftV1,
        ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
            draft
                .with_evidence_and_signature(EVIDENCE, SIGNATURE)
                .map_err(|_| ManifestOwnerAdmissionErrorV1::OwnerRejected)
        }

        fn verify_native_policy_copies(
            &self,
            _timeline_id: TimelineId,
            _scope: Hash,
            _copies: &ManifestOwnerPolicyCopiesV1,
        ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
            Ok(())
        }
    }

    impl LocalCutOwnerVerifierV1 for AcceptingOwner {
        fn verify_authenticated_cut(
            &self,
            _request: &LocalCutOwnerRequestV1,
            _current_state: Option<&LocalCutOwnerStateV1>,
            _admission_state: &ManifestOwnerAdmissionOwnerStateV1,
            _admissions: &[ManifestOwnerAdmissionSnapshotV1],
        ) -> Result<(), LocalCutOwnerErrorV1> {
            Ok(())
        }

        fn sign_local_cut_receipt(
            &self,
            commit: &LocalCutCommitV1,
        ) -> Result<LocalCutReceiptV1, LocalCutOwnerErrorV1> {
            LocalCutReceiptV1::new(LocalCutReceiptInputV1 {
                commit_record_hash: commit.digest(),
                coordinator_key_evidence_hash: EVIDENCE,
                signature: SIGNATURE,
            })
            .map_err(|_| LocalCutOwnerErrorV1::OwnerRejected)
        }

        fn verify_local_cut_receipt(
            &self,
            _receipt: &LocalCutReceiptV1,
            _commit: &LocalCutCommitV1,
            _admissions: &[ManifestOwnerAdmissionSnapshotV1],
        ) -> Result<(), LocalCutOwnerErrorV1> {
            Ok(())
        }
    }

    const fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    const fn plugin(byte: u8) -> PluginId {
        PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
    }

    const fn timeline(byte: u8) -> TimelineId {
        TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
    }

    fn policy_source(plugin_id: PluginId, seed: u8) -> FixtureResult<PolicySource> {
        let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
            plugin_id,
            plugin_version: "1.0.0".to_owned(),
            implementation_hash: hash(seed + 30),
            base_configuration_digest: hash(seed + 40),
            executable_profile_hash: hash(seed + 50),
            retention_policy_hash: hash(seed + 60),
            policy_revision: 1,
            output_declarations: Vec::new(),
        })?;
        let members = [
            policy.to_canonical_cbor(),
            b"EBP1-fixture".to_vec(),
            b"implementation-fixture".to_vec(),
            b"CFG1-fixture".to_vec(),
            Vec::new(),
            b"RTP1-fixture".to_vec(),
        ];
        let mut closure = b"OPC1".to_vec();
        for member in members {
            let length = u64::try_from(member.len())?;
            closure.extend_from_slice(&length.to_be_bytes());
            closure.extend_from_slice(&member);
        }
        Ok((policy, closure))
    }

    fn opc1_digest(bytes: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
        hasher.update(bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    fn catalog_fixture(
        owner_id: [u8; 32],
        generation: u64,
    ) -> FixtureResult<(ManifestAdmissionCatalogV1, Vec<PolicySource>)> {
        let first = policy_source(plugin(1), 1)?;
        let second = policy_source(plugin(2), 2)?;
        let sources = vec![first, second];
        let mut rows = Vec::with_capacity(sources.len());
        for (index, (policy, closure)) in sources.iter().enumerate() {
            rows.push(ManifestAdmissionCatalogRowV1 {
                stable_slot: format!("slot-{index}"),
                plugin_id: policy.fields().plugin_id,
                plugin_name: "same-name".to_owned(),
                plugin_version: policy.fields().plugin_version.clone(),
                implementation_hash: policy.fields().implementation_hash,
                eop1_native_digest: policy.digest(),
                closure_hash: opc1_digest(closure),
            });
        }
        let catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
            owner_id,
            configuration_generation: generation,
            rows,
        })?;
        Ok((catalog, sources))
    }

    fn leaf(
        owner_id: [u8; 32],
        scope: Hash,
        kind: WorldArtifactKindV1,
        native_digest: Hash,
        native_bytes: &[u8],
    ) -> FixtureResult<WorldArtifactLeafV1> {
        let leaf = WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
            scope,
            kind,
            native_digest,
            native_byte_length: u64::try_from(native_bytes.len())?,
            owner: owner_id,
            data_class: ArtifactDataClassV1::StructuralAuditMetadata,
            optionality: ArtifactOptionalityV1::Required,
            transition: ArtifactTransitionRuleV1::PreserveExact,
            source_lease_hash: hash(80),
            key_dependencies: Vec::new(),
            child_node_hashes: Vec::new(),
        })?;
        Ok(leaf)
    }

    fn policy_copy(
        owner_id: [u8; 32],
        scope: Hash,
        policy: &OutputPolicyV1,
        closure: &[u8],
    ) -> FixtureResult<ManifestOwnerPolicyCopiesV1> {
        let eop1_bytes = policy.to_canonical_cbor();
        let eop1_kind = WorldArtifactKindV1::OutputPolicy;
        let eop1_leaf = leaf(owner_id, scope, eop1_kind, policy.digest(), &eop1_bytes)?;
        let opc1_kind = WorldArtifactKindV1::OutputPolicyClosure;
        let opc1_leaf = leaf(owner_id, scope, opc1_kind, opc1_digest(closure), closure)?;
        Ok(ManifestOwnerPolicyCopiesV1 {
            plugin_id: policy.fields().plugin_id,
            eop1_bytes,
            eop1_leaf,
            opc1_bytes: closure.to_vec(),
            opc1_leaf,
        })
    }

    fn timeline_request(
        owner_id: [u8; 32],
        timeline_id: TimelineId,
        scope: Hash,
        sources: &[PolicySource],
    ) -> FixtureResult<ManifestOwnerTimelineAdmissionRequestV1> {
        let observer = "local-observer".to_owned();
        let consumer = WorldConsumerV1::new(observer, hash(130), hash(131), hash(132))?;
        let producer = WorldProducerV1::new(plugin(1), sources[0].0.digest())?;
        let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope,
            consumers: vec![consumer],
            producers: vec![producer],
            optional_view_roots: Vec::new(),
        })?;
        let mut policy_copies = Vec::with_capacity(sources.len());
        for (policy, closure) in sources {
            policy_copies.push(policy_copy(owner_id, scope, policy, closure)?);
        }
        Ok(ManifestOwnerTimelineAdmissionRequestV1 {
            timeline_id,
            scope,
            wcs1,
            policy_copies,
        })
    }

    fn admission_request(
        owner_id: [u8; 32],
        generation: u64,
        timeline_ids: &[TimelineId],
        operation_id: Hash,
        current: Option<&ManifestOwnerAdmissionOwnerStateV1>,
    ) -> FixtureResult<ManifestOwnerAdmissionRequestV1> {
        let (catalog, sources) = catalog_fixture(owner_id, generation)?;
        let mut timelines = Vec::with_capacity(timeline_ids.len());
        for (index, timeline_id) in timeline_ids.iter().enumerate() {
            let scope = hash(70 + u8::try_from(index)?);
            timelines.push(timeline_request(owner_id, *timeline_id, scope, &sources)?);
        }
        let expected_generation = current.map(|state| state.configuration_generation);
        let previous_receipt = current.and_then(|state| state.previous_visible_lcq1_hash);
        let expected_inventory = current.map(|state| state.inventory_generation);
        Ok(ManifestOwnerAdmissionRequestV1 {
            operation_id,
            catalog,
            expected_configuration_generation: expected_generation,
            previous_visible_lcq1_hash: previous_receipt,
            expected_inventory_generation: expected_inventory,
            resulting_inventory_generation: operation_id,
            timelines,
        })
    }

    fn prepare_admission(
        store: &MemoryStore,
        owner_id: [u8; 32],
        generation: u64,
        timeline_ids: &[TimelineId],
        operation_id: Hash,
    ) -> FixtureResult<PreparedManifestOwnerAdmissionV1> {
        let current = store.read_manifest_owner_state_v1(owner_id)?;
        let request = admission_request(
            owner_id,
            generation,
            timeline_ids,
            operation_id,
            current.as_ref(),
        )?;
        let prepared =
            prepare_manifest_owner_admission_v1(request, &AcceptingOwner, current.as_ref())?;
        Ok(prepared)
    }

    fn admitted_store(roster: &[([u8; 32], TimelineId)]) -> FixtureResult<MemoryStore> {
        let mut store = MemoryStore::new();
        for &(owner_id, timeline_id) in roster {
            let timelines = [timeline_id];
            let batch = prepare_admission(&store, owner_id, 1, &timelines, ADMISSION_OPERATION)?;
            store.commit_manifest_owner_admission_v1(batch)?;
        }
        Ok(store)
    }

    fn admitted_view(store: &MemoryStore, owner_id: [u8; 32]) -> FixtureResult<AdmittedView> {
        let state = store.read_manifest_owner_state_v1(owner_id)?;
        let state = state.ok_or("missing admitted owner state")?;
        let generation = state.configuration_generation;
        let mut snapshots = Vec::with_capacity(state.timelines.len());
        for timeline_id in &state.timelines {
            let snapshot =
                store.read_manifest_owner_admission_v1(owner_id, generation, *timeline_id)?;
            snapshots.push(snapshot.ok_or("missing admitted owner snapshot")?);
        }
        Ok(AdmittedView { state, snapshots })
    }

    fn table(row_count: usize, byte: u8) -> FixtureResult<LocalCutTableRefV1> {
        let rows = u64::try_from(row_count)?;
        let table = LocalCutTableRefV1::new(rows, (rows != 0).then_some(hash(byte)))?;
        Ok(table)
    }

    fn composition_row(
        row: &ManifestAdmissionCatalogRowV1,
        timeline_id: TimelineId,
    ) -> LocalCutCompositionBindingRowV1 {
        LocalCutCompositionBindingRowV1 {
            plugin_id: row.plugin_id,
            timeline_id,
            plugin_version: row.plugin_version.clone(),
            implementation_hash: row.implementation_hash,
            eop1_native_digest: row.eop1_native_digest,
            driver_interval_ns: Some(0),
            last_due_ns: None,
            event_cursor: 0,
            participant_native_state_hash: hash(91),
        }
    }

    fn cut_request(
        owner_id: [u8; 32],
        admission: &ManifestOwnerAdmissionOwnerStateV1,
        snapshots: &[ManifestOwnerAdmissionSnapshotV1],
        plan: &CutPlan,
    ) -> FixtureResult<LocalCutOwnerRequestV1> {
        let mut binding_rows = Vec::with_capacity(snapshots.len());
        let mut composition_rows = Vec::new();
        let mut recording_context_rows = Vec::with_capacity(snapshots.len());
        for snapshot in snapshots {
            let timeline = &snapshot.timeline;
            binding_rows.push(LocalCutManifestBindingRowV1 {
                timeline_id: timeline.timeline_id,
                scope: timeline.scope,
                wcs_hash: timeline.wcs1.digest(),
                msr_hash: timeline.receipt.digest(),
                msb_hash: timeline.binding.digest(),
            });
            for row in &snapshot.catalog.as_input().rows {
                composition_rows.push(composition_row(row, timeline.timeline_id));
            }
            recording_context_rows.push(LocalCutRecordingContextRowV1 {
                timeline_id: timeline.timeline_id,
                wcs_hash: timeline.wcs1.digest(),
                retention_lease_hash: hash(104),
                predecessor_wcb_hash: None,
            });
        }
        composition_rows.sort_unstable_by_key(|row| (row.plugin_id, row.timeline_id));
        let binding_table =
            LocalCutManifestBindingTableV1::new(owner_id, plan.cut_id, binding_rows)?;
        let seal = LocalCutSealV2::new(LocalCutSealInputV2 {
            owner_id,
            cut_id: plan.cut_id,
            tick: plan.tick,
            membership_epoch: plan.membership_epoch,
            configuration_generation: admission.configuration_generation,
            schedule_ns: 0,
            previous_visible_receipt_hash: admission.previous_visible_lcq1_hash,
            expected_inventory_generation: admission.inventory_generation,
            membership_table: table(snapshots.len(), 94)?,
            composition_table: table(composition_rows.len(), 92)?,
            inbox_table: table(0, 95)?,
            invocation_table: table(0, 96)?,
            expected_heads_table: table(1, 105)?,
            ebp_native_hash: hash(98),
            execution_profile_native_hash: hash(99),
            recording_context_table: table(recording_context_rows.len(), 93)?,
            owner_operational_policy_hash: hash(100),
            explicit_attempt_hash: None,
            ingress_preallocation_native_hash: hash(101),
            manifest_binding_table: binding_table.table_ref(),
        })?;
        Ok(LocalCutOwnerRequestV1 {
            operation_id: plan.operation_id,
            seal,
            manifest_hash: hash(103),
            manifest_binding_table: binding_table,
            composition_rows,
            recording_context_rows,
            partition_ledger_seq: plan.cut_id,
            result_heads_table: table(1, 105)?,
            participant_successor_table: table(1, 106)?,
            cpu_completion_table: table(0, 107)?,
            action_disposition_table: table(1, 108)?,
            candidate_bases_table: table(0, 109)?,
            invocation_bridges_table: table(0, 110)?,
            result_inventory_generation: plan.result_inventory,
            release_fence_proof_digest: hash(112),
        })
    }

    fn prepare_cut_from(
        store: &MemoryStore,
        owner_id: [u8; 32],
        plan: &CutPlan,
        current: Option<&LocalCutOwnerStateV1>,
    ) -> FixtureResult<PreparedLocalCutOwnerCommitV1> {
        let view = admitted_view(store, owner_id)?;
        let request = cut_request(owner_id, &view.state, &view.snapshots, plan)?;
        let batch = prepare_local_cut_owner_commit_v1(
            request,
            current,
            &view.state,
            &view.snapshots,
            &AcceptingOwner,
        )?;
        Ok(batch)
    }

    fn prepare_cut(
        store: &MemoryStore,
        owner_id: [u8; 32],
        plan: &CutPlan,
    ) -> FixtureResult<PreparedLocalCutOwnerCommitV1> {
        let current = store.read_local_cut_owner_state_v1(owner_id)?;
        prepare_cut_from(store, owner_id, plan, current.as_ref())
    }

    fn commit_cut(
        store: &mut MemoryStore,
        owner_id: [u8; 32],
        plan: &CutPlan,
    ) -> FixtureResult<LocalCutOwnerCommitV1> {
        let batch = prepare_cut(store, owner_id, plan)?;
        let committed = store.commit_local_cut_owner_v1(batch)?;
        Ok(committed)
    }

    fn cut_store() -> FixtureResult<(MemoryStore, LocalCutOwnerCommitV1)> {
        let mut store = admitted_store(&CUT_ROSTER)?;
        let first = commit_cut(&mut store, CUT_OWNER, &FIRST_CUT)?;
        Ok((store, first))
    }

    fn local_state(
        store: &mut MemoryStore,
        owner_id: [u8; 32],
    ) -> FixtureResult<&mut LocalCutOwnerStateV1> {
        let state = store.local_cut_owner_states.get_mut(&owner_id);
        state.ok_or_else(|| "missing local-cut owner state".into())
    }

    fn admission_state(
        store: &mut MemoryStore,
        owner_id: [u8; 32],
    ) -> FixtureResult<&mut MemoryManifestOwnerAdmissionStateV1> {
        let state = store.manifest_owner_admission_states.get_mut(&owner_id);
        state.ok_or_else(|| "missing admitted owner state".into())
    }

    fn admission_operation(
        store: &mut MemoryStore,
        owner_id: [u8; 32],
    ) -> FixtureResult<&mut MemoryManifestOwnerAdmissionOperationV1> {
        let key = (owner_id, ADMISSION_OPERATION);
        let operation = store.manifest_owner_admission_operations.get_mut(&key);
        operation.ok_or_else(|| "missing admitted owner operation".into())
    }

    fn local_operation(
        store: &mut MemoryStore,
        operation_id: Hash,
    ) -> FixtureResult<&mut MemoryLocalCutOwnerOperationV1> {
        let key = (CUT_OWNER, operation_id);
        let operation = store.local_cut_owner_operations.get_mut(&key);
        operation.ok_or_else(|| "missing local-cut operation".into())
    }

    fn assert_manifest_corrupt(store: &MemoryStore, owner_id: [u8; 32]) {
        assert_eq!(
            store.read_manifest_owner_state_v1(owner_id),
            Err(ManifestOwnerAdmissionErrorV1::CorruptState)
        );
    }

    fn assert_local_error(store: &MemoryStore, error: LocalCutOwnerErrorV1) {
        assert_eq!(store.read_local_cut_owner_state_v1(CUT_OWNER), Err(error));
    }

    #[test]
    fn owner_reads_skip_rows_owned_by_other_owners() -> TestResult {
        let roster = [(CUT_OWNER, CUT_TIMELINE), (IDLE_OWNER, IDLE_TIMELINE)];
        let mut store = admitted_store(&roster)?;
        commit_cut(&mut store, CUT_OWNER, &FIRST_CUT)?;
        assert_eq!(store.read_manifest_owner_state_v1(STRANGER), Ok(None));
        let idle = store.read_manifest_owner_state_v1(IDLE_OWNER)?;
        let idle = idle.ok_or("missing idle owner state")?;
        assert_eq!(idle.timelines, [IDLE_TIMELINE]);
        assert_eq!(idle.previous_visible_lcq1_hash, None);
        assert_eq!(store.read_local_cut_owner_state_v1(IDLE_OWNER), Ok(None));
        Ok(())
    }

    #[test]
    fn owner_reads_reject_orphaned_local_cut_rows() -> TestResult {
        let (mut store, _) = cut_store()?;
        store.local_cut_owner_states.remove(&CUT_OWNER);
        assert_manifest_corrupt(&store, CUT_OWNER);
        assert_local_error(&store, LocalCutOwnerErrorV1::CorruptState);
        assert_eq!(
            store.read_local_cut_owner_commit_v1(CUT_OWNER, 1),
            Err(LocalCutOwnerErrorV1::CorruptState)
        );
        assert_eq!(
            store.resolve_local_cut_owner_retry_v1(CUT_OWNER, FIRST_CUT.operation_id, hash(1)),
            Err(LocalCutOwnerErrorV1::CorruptState)
        );
        Ok(())
    }

    #[test]
    fn manifest_state_rejects_a_zero_generation_header() -> TestResult {
        let (mut store, _) = cut_store()?;
        let state = admission_state(&mut store, CUT_OWNER)?;
        state.configuration_generation = 0;
        assert_manifest_corrupt(&store, CUT_OWNER);
        Ok(())
    }

    #[test]
    fn owner_reads_reject_an_invalid_local_cut_state() -> TestResult {
        let (mut store, _) = cut_store()?;
        let state = local_state(&mut store, CUT_OWNER)?;
        state.configuration_generation = 0;
        assert_manifest_corrupt(&store, CUT_OWNER);
        assert_local_error(&store, LocalCutOwnerErrorV1::CorruptState);
        Ok(())
    }

    #[test]
    fn owner_reads_reject_a_desynchronized_local_cut_state() -> TestResult {
        let (mut store, _) = cut_store()?;
        let state = local_state(&mut store, CUT_OWNER)?;
        state.configuration_generation = 7;
        assert_manifest_corrupt(&store, CUT_OWNER);
        assert_local_error(&store, LocalCutOwnerErrorV1::CorruptState);
        Ok(())
    }

    #[test]
    fn manifest_state_rejects_missing_or_misfiled_snapshots() -> TestResult {
        let key = (CUT_OWNER, 1, CUT_TIMELINE);
        let (mut missing, _) = cut_store()?;
        missing.manifest_owner_admission_snapshots.remove(&key);
        assert_manifest_corrupt(&missing, CUT_OWNER);

        let (mut misfiled, _) = cut_store()?;
        let rows = &mut misfiled.manifest_owner_admission_snapshots;
        let snapshot = rows.remove(&key).ok_or("missing admitted snapshot")?;
        rows.insert((CUT_OWNER, 1, NEXT_TIMELINE), snapshot);
        assert_manifest_corrupt(&misfiled, CUT_OWNER);

        let (mut retimed, _) = cut_store()?;
        let rows = &mut retimed.manifest_owner_admission_snapshots;
        let snapshot = rows.get_mut(&key).ok_or("missing admitted snapshot")?;
        snapshot.timeline.timeline_id = NEXT_TIMELINE;
        assert_manifest_corrupt(&retimed, CUT_OWNER);
        Ok(())
    }

    #[test]
    fn manifest_state_rejects_an_inconsistent_generation_operation() -> TestResult {
        let roster = [(IDLE_OWNER, IDLE_TIMELINE)];
        let mut drifted = admitted_store(&roster)?;
        let state = admission_state(&mut drifted, IDLE_OWNER)?;
        state.inventory_generation = hash(0x99);
        assert_manifest_corrupt(&drifted, IDLE_OWNER);

        let mut missing = admitted_store(&roster)?;
        let key = (IDLE_OWNER, ADMISSION_OPERATION);
        missing.manifest_owner_admission_operations.remove(&key);
        assert_manifest_corrupt(&missing, IDLE_OWNER);

        let mut retried = admitted_store(&roster)?;
        let operation = admission_operation(&mut retried, IDLE_OWNER)?;
        operation.result.kind = ManifestOwnerAdmissionCommitKindV1::ExactRetry;
        assert_manifest_corrupt(&retried, IDLE_OWNER);
        Ok(())
    }

    #[test]
    fn successor_admission_keeps_the_epoch_for_the_same_roster() -> TestResult {
        let (mut store, first) = cut_store()?;
        let timelines = [CUT_TIMELINE];
        let batch = prepare_admission(&store, CUT_OWNER, 2, &timelines, hash(0x52))?;
        store.commit_manifest_owner_admission_v1(batch)?;
        let state = store.read_local_cut_owner_state_v1(CUT_OWNER)?;
        let state = state.ok_or("missing local-cut owner state")?;
        assert_eq!(state.membership_epoch, 0);
        assert_eq!(state.configuration_generation, 2);
        assert_eq!(state.inventory_generation, hash(0x52));
        assert_eq!(
            state.previous_visible_lcq1_hash,
            Some(first.receipt.digest())
        );
        Ok(())
    }

    #[test]
    fn successor_admission_rejects_an_exhausted_membership_epoch() -> TestResult {
        let (mut store, _) = cut_store()?;
        let state = local_state(&mut store, CUT_OWNER)?;
        state.membership_epoch = u32::MAX;
        let timelines = [NEXT_TIMELINE];
        let batch = prepare_admission(&store, CUT_OWNER, 2, &timelines, hash(0x53))?;
        assert_eq!(
            store.commit_manifest_owner_admission_v1(batch),
            Err(ManifestOwnerAdmissionErrorV1::Conflict)
        );
        Ok(())
    }

    #[test]
    fn local_cut_state_rejects_inconsistent_commit_rows() -> TestResult {
        let (mut retried, _) = cut_store()?;
        let rows = &mut retried.local_cut_owner_commits;
        let commit = rows.get_mut(&(CUT_OWNER, 1)).ok_or("missing commit")?;
        commit.kind = LocalCutOwnerCommitKindV1::ExactRetry;
        assert_local_error(&retried, LocalCutOwnerErrorV1::CorruptState);

        let (mut unlinked, _) = cut_store()?;
        let key = (CUT_OWNER, FIRST_CUT.operation_id);
        unlinked.local_cut_owner_operations.remove(&key);
        assert_local_error(&unlinked, LocalCutOwnerErrorV1::CorruptState);

        let (mut rewired, _) = cut_store()?;
        let state = local_state(&mut rewired, CUT_OWNER)?;
        state.previous_visible_lcq1_hash = Some(hash(0x98));
        let admission = admission_state(&mut rewired, CUT_OWNER)?;
        admission.previous_visible_lcq1_hash = Some(hash(0x98));
        assert_local_error(&rewired, LocalCutOwnerErrorV1::CorruptState);

        let (mut ahead, _) = cut_store()?;
        let state = local_state(&mut ahead, CUT_OWNER)?;
        state.last_visible_cut_id = 2;
        assert_local_error(&ahead, LocalCutOwnerErrorV1::CorruptState);
        Ok(())
    }

    #[test]
    fn local_cut_state_rejects_commits_after_the_visible_cut() -> TestResult {
        let (mut store, first) = cut_store()?;
        commit_cut(&mut store, CUT_OWNER, &SECOND_CUT)?;
        let rewound = Some(first.receipt.digest());
        let state = local_state(&mut store, CUT_OWNER)?;
        state.last_visible_cut_id = 1;
        state.previous_visible_lcq1_hash = rewound;
        let admission = admission_state(&mut store, CUT_OWNER)?;
        admission.previous_visible_lcq1_hash = rewound;
        assert_local_error(&store, LocalCutOwnerErrorV1::CorruptState);
        Ok(())
    }

    #[test]
    fn local_cut_reads_skip_rows_owned_by_other_owners() -> TestResult {
        let roster = [(CUT_OWNER, CUT_TIMELINE), (PEER_OWNER, PEER_TIMELINE)];
        let mut store = admitted_store(&roster)?;
        let first = commit_cut(&mut store, CUT_OWNER, &FIRST_CUT)?;
        commit_cut(&mut store, PEER_OWNER, &FIRST_CUT)?;
        let state = store.read_local_cut_owner_state_v1(CUT_OWNER)?;
        let state = state.ok_or("missing local-cut owner state")?;
        assert_eq!(
            state.previous_visible_lcq1_hash,
            Some(first.receipt.digest())
        );
        let unknown_cut = store.read_local_cut_owner_commit_v1(CUT_OWNER, 9);
        assert_eq!(unknown_cut, Ok(None));
        Ok(())
    }

    #[test]
    fn local_cut_state_rejects_inconsistent_operation_rows() -> TestResult {
        let (mut unshaped, _) = cut_store()?;
        let operation = local_operation(&mut unshaped, FIRST_CUT.operation_id)?;
        operation.request.operation_id = Hash::zero();
        assert_local_error(&unshaped, LocalCutOwnerErrorV1::BoundExceeded);

        let (mut forged, _) = cut_store()?;
        let operation = local_operation(&mut forged, FIRST_CUT.operation_id)?;
        operation.intent_digest = hash(0x97);
        assert_local_error(&forged, LocalCutOwnerErrorV1::CorruptState);

        let (mut replayed, _) = cut_store()?;
        let operation = local_operation(&mut replayed, FIRST_CUT.operation_id)?;
        let mut retried = operation.clone();
        retried.result.kind = LocalCutOwnerCommitKindV1::ExactRetry;
        let rows = &mut replayed.local_cut_owner_operations;
        rows.insert((CUT_OWNER, hash(0x96)), retried);
        assert_local_error(&replayed, LocalCutOwnerErrorV1::CorruptState);

        let (mut rekeyed, _) = cut_store()?;
        let rows = &mut rekeyed.local_cut_owner_operations;
        let operation = rows.remove(&(CUT_OWNER, FIRST_CUT.operation_id));
        let operation = operation.ok_or("missing local-cut operation")?;
        rows.insert((CUT_OWNER, hash(0x95)), operation);
        assert_local_error(&rekeyed, LocalCutOwnerErrorV1::CorruptState);
        Ok(())
    }

    #[test]
    fn local_cut_commit_recovers_an_exact_retry() -> TestResult {
        let mut store = admitted_store(&CUT_ROSTER)?;
        let batch = prepare_cut(&store, CUT_OWNER, &FIRST_CUT)?;
        let applied = store.commit_local_cut_owner_v1(batch.clone())?;
        let retried = store.commit_local_cut_owner_v1(batch)?;
        assert_eq!(applied.kind, LocalCutOwnerCommitKindV1::Applied);
        assert_eq!(retried.kind, LocalCutOwnerCommitKindV1::ExactRetry);
        assert_eq!(retried.receipt, applied.receipt);
        Ok(())
    }

    #[test]
    fn local_cut_commit_rejects_corrupt_or_missing_retained_state() -> TestResult {
        let (mut unlinked, _) = cut_store()?;
        let batch = prepare_cut(&unlinked, CUT_OWNER, &SECOND_CUT)?;
        let key = (CUT_OWNER, FIRST_CUT.operation_id);
        unlinked.local_cut_owner_operations.remove(&key);
        assert_eq!(
            unlinked.commit_local_cut_owner_v1(batch),
            Err(LocalCutOwnerErrorV1::CorruptState)
        );

        let mut corrupt = admitted_store(&CUT_ROSTER)?;
        let batch = prepare_cut(&corrupt, CUT_OWNER, &FIRST_CUT)?;
        let key = (CUT_OWNER, ADMISSION_OPERATION);
        corrupt.manifest_owner_admission_operations.remove(&key);
        assert_eq!(
            corrupt.commit_local_cut_owner_v1(batch),
            Err(LocalCutOwnerErrorV1::CorruptState)
        );

        let source = admitted_store(&CUT_ROSTER)?;
        let batch = prepare_cut(&source, CUT_OWNER, &FIRST_CUT)?;
        let mut empty = MemoryStore::new();
        assert_eq!(
            empty.commit_local_cut_owner_v1(batch),
            Err(LocalCutOwnerErrorV1::Conflict)
        );
        Ok(())
    }

    #[test]
    fn local_cut_commit_rejects_stale_or_misordered_successors() -> TestResult {
        let mut store = admitted_store(&CUT_ROSTER)?;
        let first = prepare_cut(&store, CUT_OWNER, &FIRST_CUT)?;
        let rival = prepare_cut(&store, CUT_OWNER, &RIVAL_CUT)?;
        store.commit_local_cut_owner_v1(first)?;
        assert_eq!(
            store.commit_local_cut_owner_v1(rival),
            Err(LocalCutOwnerErrorV1::Conflict)
        );

        let (mut overflowed, _) = cut_store()?;
        let batch = prepare_cut(&overflowed, CUT_OWNER, &SECOND_CUT)?;
        let state = local_state(&mut overflowed, CUT_OWNER)?;
        state.last_visible_tick = u64::MAX;
        assert_eq!(
            overflowed.commit_local_cut_owner_v1(batch),
            Err(LocalCutOwnerErrorV1::Conflict)
        );

        let (mut skipped, _) = cut_store()?;
        let batch = prepare_cut(&skipped, CUT_OWNER, &SECOND_CUT)?;
        let state = local_state(&mut skipped, CUT_OWNER)?;
        state.last_visible_tick = 5;
        assert_eq!(
            skipped.commit_local_cut_owner_v1(batch),
            Err(LocalCutOwnerErrorV1::Conflict)
        );
        Ok(())
    }

    #[test]
    fn local_cut_commit_rejects_a_first_cut_outside_epoch_zero() -> TestResult {
        let mut store = admitted_store(&CUT_ROSTER)?;
        let view = admitted_view(&store, CUT_OWNER)?;
        let assumed = LocalCutOwnerStateV1 {
            owner_id: CUT_OWNER,
            last_visible_cut_id: 0,
            last_visible_tick: 0,
            membership_epoch: EPOCH_CUT.membership_epoch,
            configuration_generation: view.state.configuration_generation,
            previous_visible_lcq1_hash: None,
            inventory_generation: view.state.inventory_generation,
            timelines: view.state.timelines,
        };
        let batch = prepare_cut_from(&store, CUT_OWNER, &EPOCH_CUT, Some(&assumed))?;
        assert_eq!(
            store.commit_local_cut_owner_v1(batch),
            Err(LocalCutOwnerErrorV1::Conflict)
        );
        Ok(())
    }
}
