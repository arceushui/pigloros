//! Installed-owner validation and atomic persistence boundary for local cuts.
//!
//! Portable LCS2, LCC1, LCQ1, and kind-14 records deliberately do not grant
//! cut authority. This module makes the complete admitted owner state, kind-1
//! composition bindings, kind-8 recording contexts, manifest binding, result
//! inventory, and coordinator receipt one verified transaction input.

use std::collections::BTreeMap;

use crate::local_cut_commit::{LocalCutCommitInputV1, LocalCutCommitV1, LocalCutReceiptV1};
use crate::local_cut_seal::{
    local_cut_tree_scope_v1, LocalCutManifestBindingTableV1, LocalCutSealV2, LocalCutTableRefV1,
};
use crate::manifest_owner_admission::{
    validate_manifest_owner_admission_snapshot_v1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionOwnerStateV1, ManifestOwnerAdmissionSnapshotV1,
};
use crate::{Hash, ManifestAdmissionCatalogV1, PluginId, TimelineId};

/// Maximum kind-1 or kind-8 rows that one local owner cut can select.
pub const MAX_LOCAL_CUT_OWNER_ROWS_V1: usize = 1_048_576;

const INTENT_DOMAIN: &[u8] = b"pigloros.local-cut.owner.intent.v1\0";

/// Closed owner preparation and persistence failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalCutOwnerErrorV1 {
    /// One prospective row or table exceeds the installed local-cut bounds.
    #[error("local-cut owner request exceeds its accepted bounds")]
    BoundExceeded,
    /// The submitted rows, seal, admission, or result cannot form one cut.
    #[error("local-cut owner request is not one complete canonical batch")]
    InvalidBatch,
    /// The installed owner rejected current authority, native state, or signing.
    #[error("installed local-cut owner rejected the requested cut")]
    OwnerRejected,
    /// The owner pre-state, operation, cut identity, or inventory CAS conflicts.
    #[error("local-cut owner request conflicts with persisted state")]
    Conflict,
    /// A durable owner, admission, or immutable cut record is structurally corrupt.
    #[error("local-cut owner storage contains a corrupt record")]
    CorruptState,
    /// The durable transaction outcome could not be determined.
    #[error("local-cut owner storage outcome is unavailable")]
    StorageFailure,
}

/// Read an admitted-owner failure through the local-cut boundary.
///
/// Retryable conflict and storage classes are preserved; every other admitted
/// owner failure means the shared owner boundary is corrupt.
impl From<ManifestOwnerAdmissionErrorV1> for LocalCutOwnerErrorV1 {
    fn from(error: ManifestOwnerAdmissionErrorV1) -> Self {
        match error {
            ManifestOwnerAdmissionErrorV1::Conflict => Self::Conflict,
            ManifestOwnerAdmissionErrorV1::StorageFailure => Self::StorageFailure,
            ManifestOwnerAdmissionErrorV1::BoundExceeded
            | ManifestOwnerAdmissionErrorV1::InvalidBatch
            | ManifestOwnerAdmissionErrorV1::OwnerRejected
            | ManifestOwnerAdmissionErrorV1::CorruptState => Self::CorruptState,
        }
    }
}

/// Read a local-cut owner failure through the admitted-owner boundary.
///
/// Retryable conflict and storage classes are preserved; every other local-cut
/// failure means the shared owner boundary is corrupt.
impl From<LocalCutOwnerErrorV1> for ManifestOwnerAdmissionErrorV1 {
    fn from(error: LocalCutOwnerErrorV1) -> Self {
        match error {
            LocalCutOwnerErrorV1::Conflict => Self::Conflict,
            LocalCutOwnerErrorV1::StorageFailure => Self::StorageFailure,
            LocalCutOwnerErrorV1::BoundExceeded
            | LocalCutOwnerErrorV1::InvalidBatch
            | LocalCutOwnerErrorV1::OwnerRejected
            | LocalCutOwnerErrorV1::CorruptState => Self::CorruptState,
        }
    }
}

/// One complete kind-1 composition binding selected for a prospective cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutCompositionBindingRowV1 {
    /// Exact registered Plugin identity.
    pub plugin_id: PluginId,
    /// Exact owned Timeline identity.
    pub timeline_id: TimelineId,
    /// Static registered Plugin version.
    pub plugin_version: String,
    /// Static registered implementation pin.
    pub implementation_hash: Hash,
    /// Static registered EOP1 native digest.
    pub eop1_native_digest: Hash,
    /// Installed Driver cadence; null means that the Plugin has no Driver.
    pub driver_interval_ns: Option<u64>,
    /// Last visible successful due instant for this Plugin and Timeline.
    pub last_due_ns: Option<u64>,
    /// Installed Driver event cursor at the sealed pre-Driver boundary.
    pub event_cursor: u64,
    /// Installed participant checkpoint state digest.
    pub participant_native_state_hash: Hash,
}

/// One complete kind-8 recording context selected for a prospective cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCutRecordingContextRowV1 {
    /// Exact owned Timeline identity.
    pub timeline_id: TimelineId,
    /// Exact selected WCS1 digest.
    pub wcs_hash: Hash,
    /// Installed RLS1 native retention-lease digest.
    pub retention_lease_hash: Hash,
    /// Previous WCB hash when the Timeline has a prior visible binding.
    pub predecessor_wcb_hash: Option<Hash>,
}

/// Untrusted prospective local-cut owner transaction input.
///
/// The request carries portable rows and content addresses. The installed owner
/// port authenticates its local roster, mutable participant state, retention
/// lease, manifest, inventory, and coordinator signing role before commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutOwnerRequestV1 {
    /// Nonzero durable idempotency identity allocated by the local owner.
    pub operation_id: Hash,
    /// Exact selected LCS2 seal.
    pub seal: LocalCutSealV2,
    /// Exact selected native LCM1 manifest digest.
    pub manifest_hash: Hash,
    /// Complete canonical kind-14 manifest bindings for the selected cut.
    pub manifest_binding_table: LocalCutManifestBindingTableV1,
    /// Complete canonical kind-1 composition binding set.
    pub composition_rows: Vec<LocalCutCompositionBindingRowV1>,
    /// Complete canonical kind-8 recording-context set.
    pub recording_context_rows: Vec<LocalCutRecordingContextRowV1>,
    /// Positive partition commit-ledger coordinate allocated by the owner.
    pub partition_ledger_seq: u64,
    /// Exact complete kind-5 result-head table reference.
    pub result_heads_table: LocalCutTableRefV1,
    /// Exact complete kind-7 participant-successor table reference.
    pub participant_successor_table: LocalCutTableRefV1,
    /// Exact complete CPU completion table reference.
    pub cpu_completion_table: LocalCutTableRefV1,
    /// Exact complete action-disposition table reference.
    pub action_disposition_table: LocalCutTableRefV1,
    /// Exact private candidate-base table reference.
    pub candidate_bases_table: LocalCutTableRefV1,
    /// Exact private invocation-bridge table reference.
    pub invocation_bridges_table: LocalCutTableRefV1,
    /// Fresh opaque inventory generation published with the visible receipt.
    pub result_inventory_generation: Hash,
    /// Fresh serialized release-fence proof digest.
    pub release_fence_proof_digest: Hash,
}

/// Current durable subset of the local world-cut owner state.
///
/// The store validates this state against the current admitted owner state
/// before publishing a successor. It is not a public authority constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutOwnerStateV1 {
    /// Exclusive local owner identity.
    pub owner_id: [u8; 32],
    /// Last visible globally allocated cut identity, zero before the first cut.
    pub last_visible_cut_id: u64,
    /// Last visible logical tick, zero before the first cut.
    pub last_visible_tick: u64,
    /// Current membership boundary epoch.
    pub membership_epoch: u32,
    /// Current admitted configuration generation for the next visible cut.
    ///
    /// This advances when successor admission replaces the live owner scope,
    /// even when the latest visible cut remains in the prior generation.
    pub configuration_generation: u64,
    /// Last visible LCQ1 receipt, absent only before the first cut.
    pub previous_visible_lcq1_hash: Option<Hash>,
    /// Current opaque inventory generation.
    pub inventory_generation: Hash,
    /// Current admitted Timeline roster for the next visible cut.
    ///
    /// This advances with successor admission while historical cut records keep
    /// the roster selected at each visible cut.
    pub timelines: Vec<TimelineId>,
}

impl LocalCutOwnerStateV1 {
    /// Validate a persisted owner state without granting authority.
    ///
    /// # Errors
    /// Returns `CorruptState` when counters, addresses, or the complete Timeline
    /// roster cannot describe one visible owner state.
    pub fn validate(&self) -> Result<(), LocalCutOwnerErrorV1> {
        if self.owner_id == [0; 32]
            || self.configuration_generation == 0
            || self.inventory_generation == Hash::zero()
            || self.timelines.is_empty()
            || self.timelines.len() > MAX_LOCAL_CUT_OWNER_ROWS_V1
            || self
                .timelines
                .iter()
                .any(|timeline| timeline.inner().to_bytes() == [0; 16])
            || self.timelines.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .previous_visible_lcq1_hash
                .is_some_and(|hash| hash == Hash::zero())
        {
            return Err(LocalCutOwnerErrorV1::CorruptState);
        }
        let no_visible_cut = self.last_visible_cut_id == 0;
        if no_visible_cut != self.previous_visible_lcq1_hash.is_none()
            || no_visible_cut != (self.last_visible_tick == 0)
        {
            return Err(LocalCutOwnerErrorV1::CorruptState);
        }
        Ok(())
    }
}

/// Trusted local checks and coordinator signing performed by the installed host.
///
/// A remote caller's implementation of this trait is never a source of owner
/// authority. The runtime constructs this port only from the installed local
/// owner, registry, retention, inventory, and coordinator-key providers.
pub trait LocalCutOwnerVerifierV1: Send + Sync {
    /// Authenticate every owner-selected portable and native input before LCC1.
    ///
    /// This includes the actual complete roster, current kind-1 mutable fields,
    /// kind-8 retention and predecessor contexts, table references, manifest,
    /// allocation, result inventory, release fence, and installed coordinator
    /// identity. Matching submitted digests alone must be rejected.
    ///
    /// # Errors
    /// Returns `OwnerRejected` when an input is stale, partial, caller-selected,
    /// unsigned, unavailable, or differs from installed owner state.
    fn verify_authenticated_cut(
        &self,
        request: &LocalCutOwnerRequestV1,
        current_state: Option<&LocalCutOwnerStateV1>,
        admission_state: &ManifestOwnerAdmissionOwnerStateV1,
        admissions: &[ManifestOwnerAdmissionSnapshotV1],
    ) -> Result<(), LocalCutOwnerErrorV1>;

    /// Sign the exact LCC1 content address through the installed coordinator role.
    ///
    /// The implementation chooses retained key evidence itself and signs the
    /// exact LCQ1 signature preimage. It must not accept caller-supplied key
    /// evidence or signature bytes as authority.
    ///
    /// # Errors
    /// Returns `OwnerRejected` when the active installed coordinator role cannot
    /// authenticate, sign, or retain the required evidence.
    fn sign_local_cut_receipt(
        &self,
        commit: &LocalCutCommitV1,
    ) -> Result<LocalCutReceiptV1, LocalCutOwnerErrorV1>;

    /// Verify the returned receipt against current installed coordinator authority.
    ///
    /// # Errors
    /// Returns `OwnerRejected` for an inactive, substituted, wrong-role, or
    /// invalid signature/evidence pair.
    fn verify_local_cut_receipt(
        &self,
        receipt: &LocalCutReceiptV1,
        commit: &LocalCutCommitV1,
        admissions: &[ManifestOwnerAdmissionSnapshotV1],
    ) -> Result<(), LocalCutOwnerErrorV1>;
}

/// Complete verified input which one same-store transaction may publish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLocalCutOwnerCommitV1 {
    request: LocalCutOwnerRequestV1,
    intent_digest: Hash,
    commit: LocalCutCommitV1,
    receipt: LocalCutReceiptV1,
    successor_state: LocalCutOwnerStateV1,
}

impl PreparedLocalCutOwnerCommitV1 {
    /// Borrow the exact verified request retained for atomic persistence.
    #[must_use]
    pub const fn request(&self) -> &LocalCutOwnerRequestV1 {
        &self.request
    }

    /// Return the stable unsigned idempotency digest.
    #[must_use]
    pub const fn intent_digest(&self) -> Hash {
        self.intent_digest
    }

    /// Borrow the exact LCC1 record selected by the installed owner.
    #[must_use]
    pub const fn commit(&self) -> &LocalCutCommitV1 {
        &self.commit
    }

    /// Borrow the exact installed-coordinator LCQ1 receipt.
    #[must_use]
    pub const fn receipt(&self) -> &LocalCutReceiptV1 {
        &self.receipt
    }

    /// Borrow the fully validated durable owner successor state.
    #[must_use]
    pub const fn successor_state(&self) -> &LocalCutOwnerStateV1 {
        &self.successor_state
    }

    /// Return the durable result produced when this batch first applies.
    #[must_use]
    pub const fn applied_result(&self) -> LocalCutOwnerCommitV1 {
        LocalCutOwnerCommitV1 {
            kind: LocalCutOwnerCommitKindV1::Applied,
            seal: self.request.seal,
            commit: self.commit,
            receipt: self.receipt,
        }
    }
}

/// Whether a local-cut owner operation applied or recovered exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalCutOwnerCommitKindV1 {
    /// The complete cut, receipt, owner state, and inventory became visible.
    Applied,
    /// The operation identity resolved to its exact prior committed result.
    ExactRetry,
}

/// Durable result for one local-cut owner operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCutOwnerCommitV1 {
    /// Whether this invocation applied a successor or recovered one.
    pub kind: LocalCutOwnerCommitKindV1,
    /// Exact visible LCS2 seal.
    pub seal: LocalCutSealV2,
    /// Exact immutable LCC1 commit record.
    pub commit: LocalCutCommitV1,
    /// Exact installed-coordinator LCQ1 receipt.
    pub receipt: LocalCutReceiptV1,
}

/// Same-store port for local-cut state, historical records, and retry recovery.
pub trait LocalCutOwnerPersistencePortV1 {
    /// Load the current local owner state, if the owner has made a visible cut.
    ///
    /// # Errors
    /// Returns `CorruptState` for an internally inconsistent owner/admission
    /// boundary and `StorageFailure` when the backend cannot provide a snapshot.
    fn read_local_cut_owner_state_v1(
        &self,
        owner_id: [u8; 32],
    ) -> Result<Option<LocalCutOwnerStateV1>, LocalCutOwnerErrorV1>;

    /// Resolve a prior operation before the installed coordinator signs again.
    ///
    /// An identical intent returns `ExactRetry`. Reusing the same operation for a
    /// different intent returns Conflict.
    ///
    /// # Errors
    /// Returns `Conflict` for operation reuse, `CorruptState` for invalid retained
    /// records, or `StorageFailure` when recovery cannot be determined.
    fn resolve_local_cut_owner_retry_v1(
        &self,
        owner_id: [u8; 32],
        operation_id: Hash,
        intent_digest: Hash,
    ) -> Result<Option<LocalCutOwnerCommitV1>, LocalCutOwnerErrorV1>;

    /// Atomically CAS and publish the complete selected local cut.
    ///
    /// This updates current owner visibility together with the corresponding
    /// admitted owner state's receipt and inventory generation. It must persist
    /// every supplied immutable record before exposing any successor state.
    ///
    /// # Errors
    /// Returns `Conflict`, `CorruptState`, or `StorageFailure` and exposes no partial
    /// cut, state, inventory, or receipt on failure.
    fn commit_local_cut_owner_v1(
        &mut self,
        batch: PreparedLocalCutOwnerCommitV1,
    ) -> Result<LocalCutOwnerCommitV1, LocalCutOwnerErrorV1>;

    /// Read one historical visible cut selected by immutable owner and cut keys.
    ///
    /// # Errors
    /// Returns `CorruptState` when retained records fail their exact structural
    /// identities or `StorageFailure` when the backend cannot read them.
    fn read_local_cut_owner_commit_v1(
        &self,
        owner_id: [u8; 32],
        cut_id: u64,
    ) -> Result<Option<LocalCutOwnerCommitV1>, LocalCutOwnerErrorV1>;
}

/// Derive the stable unsigned operation digest used for lost-reply recovery.
///
/// # Errors
/// Returns an error before hashing an incomplete or malformed request.
pub fn local_cut_owner_intent_digest_v1(
    request: &LocalCutOwnerRequestV1,
) -> Result<Hash, LocalCutOwnerErrorV1> {
    validate_request_shape(request)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(INTENT_DOMAIN);
    hash_part(&mut hasher, request.operation_id.as_bytes());
    hash_part(&mut hasher, &request.seal.to_canonical_cbor());
    hash_part(&mut hasher, request.manifest_hash.as_bytes());
    hash_table_ref(&mut hasher, request.manifest_binding_table.table_ref());
    hash_count(&mut hasher, request.composition_rows.len());
    for row in &request.composition_rows {
        hasher.update(b"composition\0");
        hash_part(&mut hasher, &row.plugin_id.inner().to_bytes());
        hash_part(&mut hasher, &row.timeline_id.inner().to_bytes());
        hash_part(&mut hasher, row.plugin_version.as_bytes());
        hash_part(&mut hasher, row.implementation_hash.as_bytes());
        hash_part(&mut hasher, row.eop1_native_digest.as_bytes());
        hash_optional_u64(&mut hasher, row.driver_interval_ns);
        hash_optional_u64(&mut hasher, row.last_due_ns);
        hash_part(&mut hasher, &row.event_cursor.to_be_bytes());
        hash_part(&mut hasher, row.participant_native_state_hash.as_bytes());
    }
    hash_count(&mut hasher, request.recording_context_rows.len());
    for row in &request.recording_context_rows {
        hasher.update(b"recording-context\0");
        hash_part(&mut hasher, &row.timeline_id.inner().to_bytes());
        hash_part(&mut hasher, row.wcs_hash.as_bytes());
        hash_part(&mut hasher, row.retention_lease_hash.as_bytes());
        hash_optional_hash(&mut hasher, row.predecessor_wcb_hash);
    }
    hash_part(&mut hasher, &request.partition_ledger_seq.to_be_bytes());
    for reference in [
        request.result_heads_table,
        request.participant_successor_table,
        request.cpu_completion_table,
        request.action_disposition_table,
        request.candidate_bases_table,
        request.invocation_bridges_table,
    ] {
        hash_table_ref(&mut hasher, reference);
    }
    hash_part(&mut hasher, request.result_inventory_generation.as_bytes());
    hash_part(&mut hasher, request.release_fence_proof_digest.as_bytes());
    Ok(Hash::from_bytes(*hasher.finalize().as_bytes()))
}

/// Verify a complete admitted selection, build LCC1, and obtain its LCQ1 receipt.
///
/// # Errors
/// Rejects partial or stale admission, missing kind-1/kind-8/kind-14 rows,
/// substituted static Plugin pins, duplicate cut identity, wrong owner state,
/// unverified result inventory, or any signer/key-role mismatch. The request
/// cannot supply authority, evidence, or a signature.
pub fn prepare_local_cut_owner_commit_v1(
    request: LocalCutOwnerRequestV1,
    current_state: Option<&LocalCutOwnerStateV1>,
    admission_state: &ManifestOwnerAdmissionOwnerStateV1,
    admissions: &[ManifestOwnerAdmissionSnapshotV1],
    verifier: &dyn LocalCutOwnerVerifierV1,
) -> Result<PreparedLocalCutOwnerCommitV1, LocalCutOwnerErrorV1> {
    let intent_digest = local_cut_owner_intent_digest_v1(&request)?;
    validate_admission_state(admission_state)?;
    if let Some(state) = current_state {
        state.validate()?;
    }
    let catalog = validate_current_admissions(admission_state, admissions)?;
    validate_seal_prestate(&request, current_state, admission_state)?;
    validate_manifest_binding(&request, admission_state, admissions)?;
    validate_composition_bindings(&request.composition_rows, admission_state, catalog)?;
    validate_recording_contexts(&request.recording_context_rows, admissions)?;
    verifier.verify_authenticated_cut(&request, current_state, admission_state, admissions)?;

    // The request shape already rejected every zero LCC1 identity, and the
    // seal address is a BLAKE3 digest, so the commit fields are structurally valid.
    let seal_hash = request.seal.digest();
    let commit = LocalCutCommitV1::from_owner_validated(&LocalCutCommitInputV1 {
        owner_id: request.seal.as_input().owner_id,
        cut_id: request.seal.as_input().cut_id,
        partition_ledger_seq: request.partition_ledger_seq,
        seal_hash,
        manifest_hash: request.manifest_hash,
        result_heads_table: request.result_heads_table,
        participant_successor_table: request.participant_successor_table,
        cpu_completion_table: request.cpu_completion_table,
        action_disposition_table: request.action_disposition_table,
        candidate_bases_table: request.candidate_bases_table,
        invocation_bridges_table: request.invocation_bridges_table,
        result_inventory_generation: request.result_inventory_generation,
        release_fence_proof_digest: request.release_fence_proof_digest,
    });
    let receipt = verifier.sign_local_cut_receipt(&commit)?;
    if receipt.as_input().commit_record_hash != commit.digest()
        || admissions.iter().any(|snapshot| {
            snapshot
                .timeline
                .receipt
                .as_input()
                .coordinator_key_evidence_hash
                != receipt.as_input().coordinator_key_evidence_hash
        })
    {
        return Err(LocalCutOwnerErrorV1::OwnerRejected);
    }
    verifier.verify_local_cut_receipt(&receipt, &commit, admissions)?;

    // Every field comes from the validated admission state, request, LCS2 seal
    // (positive cut and tick), or a BLAKE3 receipt digest, so the successor is
    // a valid visible owner state by construction.
    let successor_state = LocalCutOwnerStateV1 {
        owner_id: admission_state.owner_id,
        last_visible_cut_id: request.seal.as_input().cut_id,
        last_visible_tick: request.seal.as_input().tick,
        membership_epoch: request.seal.as_input().membership_epoch,
        configuration_generation: admission_state.configuration_generation,
        previous_visible_lcq1_hash: Some(receipt.digest()),
        inventory_generation: request.result_inventory_generation,
        timelines: admission_state.timelines.clone(),
    };
    Ok(PreparedLocalCutOwnerCommitV1 {
        request,
        intent_digest,
        commit,
        receipt,
        successor_state,
    })
}

/// Validate one retained applied result against its owner and cut keys.
///
/// # Errors
/// Returns `CorruptState` unless the result is an applied LCS2, LCC1, and LCQ1
/// chain keyed by exactly `owner_id` and `cut_id`.
pub fn validate_local_cut_owner_result_v1(
    owner_id: [u8; 32],
    cut_id: u64,
    result: &LocalCutOwnerCommitV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    let seal = result.seal.as_input();
    let commit = result.commit.as_input();
    let receipt = result.receipt.as_input();
    if result.kind != LocalCutOwnerCommitKindV1::Applied
        || seal.owner_id != owner_id
        || seal.cut_id != cut_id
        || commit.owner_id != owner_id
        || commit.cut_id != cut_id
        || commit.seal_hash != result.seal.digest()
        || receipt.commit_record_hash != result.commit.digest()
        || result.receipt.digest() == Hash::zero()
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(())
}

/// Compare a prepared batch with the persisted owner pre-state it replaces.
///
/// Preparation derived the intent, LCC1 and LCQ1 result, and successor state
/// from the request, its seal, and the admitted state it was built against, so
/// only the admitted and local-cut state read inside the commit transaction can
/// differ here.
///
/// # Errors
/// Returns `Conflict` when the current admitted state or local-cut owner state
/// no longer matches the seal pre-state, the successor roster, or the next cut,
/// tick, and membership epoch.
pub fn validate_local_cut_owner_successor_v1(
    batch: &PreparedLocalCutOwnerCommitV1,
    admission: &ManifestOwnerAdmissionOwnerStateV1,
    current_state: Option<&LocalCutOwnerStateV1>,
) -> Result<(), LocalCutOwnerErrorV1> {
    let seal = batch.request.seal.as_input();
    let successor = &batch.successor_state;
    if seal.configuration_generation != admission.configuration_generation
        || seal.previous_visible_receipt_hash != admission.previous_visible_lcq1_hash
        || seal.expected_inventory_generation != admission.inventory_generation
        || successor.timelines != admission.timelines
    {
        return Err(LocalCutOwnerErrorV1::Conflict);
    }
    match current_state {
        Some(state) => {
            let expected_tick = state
                .last_visible_tick
                .checked_add(1)
                .ok_or(LocalCutOwnerErrorV1::Conflict)?;
            if successor.last_visible_cut_id <= state.last_visible_cut_id
                || successor.last_visible_tick != expected_tick
                || successor.membership_epoch != state.membership_epoch
            {
                return Err(LocalCutOwnerErrorV1::Conflict);
            }
        }
        None => {
            if successor.last_visible_tick != 1 || successor.membership_epoch != 0 {
                return Err(LocalCutOwnerErrorV1::Conflict);
            }
        }
    }
    Ok(())
}

fn validate_request_shape(request: &LocalCutOwnerRequestV1) -> Result<(), LocalCutOwnerErrorV1> {
    if request.operation_id == Hash::zero()
        || request.manifest_hash == Hash::zero()
        || request.partition_ledger_seq == 0
        || request.result_inventory_generation == Hash::zero()
        || request.release_fence_proof_digest == Hash::zero()
        || request.composition_rows.is_empty()
        || request.recording_context_rows.is_empty()
        || request.composition_rows.len() > MAX_LOCAL_CUT_OWNER_ROWS_V1
        || request.recording_context_rows.len() > MAX_LOCAL_CUT_OWNER_ROWS_V1
        || request.manifest_binding_table.rows().is_empty()
        || request.manifest_binding_table.rows().len() > MAX_LOCAL_CUT_OWNER_ROWS_V1
    {
        return Err(LocalCutOwnerErrorV1::BoundExceeded);
    }
    if request.seal.as_input().owner_id == [0; 32]
        || request.result_inventory_generation
            == request.seal.as_input().expected_inventory_generation
        || request.manifest_binding_table.tree_scope()
            != local_cut_tree_scope_v1(
                request.seal.as_input().owner_id,
                request.seal.as_input().cut_id,
            )
        || request.manifest_binding_table.table_ref()
            != request.seal.as_input().manifest_binding_table
        || request.composition_rows.len() as u64
            != request.seal.as_input().composition_table.row_count()
        || request.recording_context_rows.len() as u64
            != request.seal.as_input().recording_context_table.row_count()
    {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    validate_composition_row_order(&request.composition_rows)?;
    validate_recording_context_row_order(&request.recording_context_rows)?;
    Ok(())
}

fn validate_admission_state(
    admission_state: &ManifestOwnerAdmissionOwnerStateV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    if admission_state.owner_id == [0; 32]
        || admission_state.configuration_generation == 0
        || admission_state.inventory_generation == Hash::zero()
        || admission_state.timelines.is_empty()
        || admission_state.timelines.len() > MAX_LOCAL_CUT_OWNER_ROWS_V1
        || admission_state
            .previous_visible_lcq1_hash
            .is_some_and(|hash| hash == Hash::zero())
        || admission_state
            .timelines
            .iter()
            .any(|timeline| timeline.inner().to_bytes() == [0; 16])
        || admission_state
            .timelines
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    Ok(())
}

fn validate_current_admissions<'a>(
    admission_state: &ManifestOwnerAdmissionOwnerStateV1,
    admissions: &'a [ManifestOwnerAdmissionSnapshotV1],
) -> Result<&'a ManifestAdmissionCatalogV1, LocalCutOwnerErrorV1> {
    if admissions.len() != admission_state.timelines.len() || admissions.is_empty() {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    let catalog = &admissions[0].catalog;
    if catalog.as_input().owner_id != admission_state.owner_id
        || catalog.as_input().configuration_generation != admission_state.configuration_generation
        || catalog.as_input().rows.is_empty()
    {
        return Err(LocalCutOwnerErrorV1::CorruptState);
    }
    for (snapshot, timeline_id) in admissions.iter().zip(&admission_state.timelines) {
        // Snapshot validation only produces BoundExceeded or InvalidBatch.
        validate_manifest_owner_admission_snapshot_v1(snapshot)
            .map_err(|_| LocalCutOwnerErrorV1::CorruptState)?;
        if &snapshot.catalog != catalog
            || snapshot.timeline.timeline_id != *timeline_id
            || snapshot.catalog.as_input().owner_id != admission_state.owner_id
            || snapshot.catalog.as_input().configuration_generation
                != admission_state.configuration_generation
        {
            return Err(LocalCutOwnerErrorV1::CorruptState);
        }
    }
    Ok(catalog)
}

fn validate_seal_prestate(
    request: &LocalCutOwnerRequestV1,
    current_state: Option<&LocalCutOwnerStateV1>,
    admission_state: &ManifestOwnerAdmissionOwnerStateV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    let seal = request.seal.as_input();
    let expected_previous_receipt_hash = admission_state.previous_visible_lcq1_hash;
    if seal.owner_id != admission_state.owner_id
        || seal.configuration_generation != admission_state.configuration_generation
        || seal.previous_visible_receipt_hash != expected_previous_receipt_hash
        || seal.expected_inventory_generation != admission_state.inventory_generation
    {
        return Err(LocalCutOwnerErrorV1::Conflict);
    }
    match current_state {
        Some(state) => {
            let last_visible_cut_id = state.last_visible_cut_id;
            let expected_tick = state
                .last_visible_tick
                .checked_add(1)
                .ok_or(LocalCutOwnerErrorV1::BoundExceeded)?;
            if state.owner_id != admission_state.owner_id
                || state.previous_visible_lcq1_hash != admission_state.previous_visible_lcq1_hash
                || state.configuration_generation != admission_state.configuration_generation
                || state.inventory_generation != admission_state.inventory_generation
                || state.timelines != admission_state.timelines
                || seal.cut_id <= last_visible_cut_id
                || seal.tick != expected_tick
                || seal.membership_epoch != state.membership_epoch
            {
                return Err(LocalCutOwnerErrorV1::Conflict);
            }
        }
        None => {
            if admission_state.previous_visible_lcq1_hash.is_some()
                || seal.tick != 1
                || seal.membership_epoch != 0
            {
                return Err(LocalCutOwnerErrorV1::CorruptState);
            }
        }
    }
    Ok(())
}

fn validate_manifest_binding(
    request: &LocalCutOwnerRequestV1,
    admission_state: &ManifestOwnerAdmissionOwnerStateV1,
    admissions: &[ManifestOwnerAdmissionSnapshotV1],
) -> Result<(), LocalCutOwnerErrorV1> {
    let rows = request.manifest_binding_table.rows();
    if rows.len() != admissions.len() || rows.len() != admission_state.timelines.len() {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    for ((row, snapshot), timeline_id) in
        rows.iter().zip(admissions).zip(&admission_state.timelines)
    {
        if row.timeline_id != *timeline_id
            || row.timeline_id != snapshot.timeline.timeline_id
            || row.scope != snapshot.timeline.scope
            || row.wcs_hash != snapshot.timeline.wcs1.digest()
            || row.msr_hash != snapshot.timeline.receipt.digest()
            || row.msb_hash != snapshot.timeline.binding.digest()
        {
            return Err(LocalCutOwnerErrorV1::InvalidBatch);
        }
    }
    Ok(())
}

fn validate_composition_bindings(
    rows: &[LocalCutCompositionBindingRowV1],
    admission_state: &ManifestOwnerAdmissionOwnerStateV1,
    catalog: &ManifestAdmissionCatalogV1,
) -> Result<(), LocalCutOwnerErrorV1> {
    // At most 256 catalog rows times 1,048,576 Timelines cannot overflow.
    let expected = catalog.as_input().rows.len() * admission_state.timelines.len();
    if rows.len() != expected {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    let catalog_rows = catalog
        .as_input()
        .rows
        .iter()
        .map(|row| (row.plugin_id, row))
        .collect::<BTreeMap<PluginId, _>>();
    for row in rows {
        let catalog_row = catalog_rows
            .get(&row.plugin_id)
            .ok_or(LocalCutOwnerErrorV1::InvalidBatch)?;
        if admission_state
            .timelines
            .binary_search(&row.timeline_id)
            .is_err()
            || row.plugin_version != catalog_row.plugin_version
            || row.implementation_hash != catalog_row.implementation_hash
            || row.eop1_native_digest != catalog_row.eop1_native_digest
        {
            return Err(LocalCutOwnerErrorV1::InvalidBatch);
        }
    }
    Ok(())
}

fn validate_recording_contexts(
    rows: &[LocalCutRecordingContextRowV1],
    admissions: &[ManifestOwnerAdmissionSnapshotV1],
) -> Result<(), LocalCutOwnerErrorV1> {
    if rows.len() != admissions.len() {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    for (row, snapshot) in rows.iter().zip(admissions) {
        if row.timeline_id != snapshot.timeline.timeline_id
            || row.wcs_hash != snapshot.timeline.wcs1.digest()
        {
            return Err(LocalCutOwnerErrorV1::InvalidBatch);
        }
    }
    Ok(())
}

fn validate_composition_row_order(
    rows: &[LocalCutCompositionBindingRowV1],
) -> Result<(), LocalCutOwnerErrorV1> {
    if rows.iter().any(|row| {
        row.plugin_id.inner().to_bytes() == [0; 16]
            || row.timeline_id.inner().to_bytes() == [0; 16]
            || row.plugin_version.is_empty()
            || row.plugin_version.len() > 64
            || row.implementation_hash == Hash::zero()
            || row.eop1_native_digest == Hash::zero()
            || row.participant_native_state_hash == Hash::zero()
            || (row.driver_interval_ns.is_none() && row.last_due_ns.is_some())
    }) || rows.windows(2).any(|pair| {
        (pair[0].plugin_id, pair[0].timeline_id) >= (pair[1].plugin_id, pair[1].timeline_id)
    }) {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    Ok(())
}

fn validate_recording_context_row_order(
    rows: &[LocalCutRecordingContextRowV1],
) -> Result<(), LocalCutOwnerErrorV1> {
    if rows.iter().any(|row| {
        row.timeline_id.inner().to_bytes() == [0; 16]
            || row.wcs_hash == Hash::zero()
            || row.retention_lease_hash == Hash::zero()
            || row.predecessor_wcb_hash == Some(Hash::zero())
    }) || rows
        .windows(2)
        .any(|pair| pair[0].timeline_id >= pair[1].timeline_id)
    {
        return Err(LocalCutOwnerErrorV1::InvalidBatch);
    }
    Ok(())
}

fn hash_count(hasher: &mut blake3::Hasher, count: usize) {
    hasher.update(&(count as u64).to_be_bytes());
}

fn hash_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hash_optional_hash(hasher: &mut blake3::Hasher, value: Option<Hash>) {
    if let Some(value) = value {
        hasher.update(&[1]);
        hash_part(hasher, value.as_bytes());
    } else {
        hasher.update(&[0]);
    }
}

fn hash_optional_u64(hasher: &mut blake3::Hasher, value: Option<u64>) {
    if let Some(value) = value {
        hasher.update(&[1]);
        hash_part(hasher, &value.to_be_bytes());
    } else {
        hasher.update(&[0]);
    }
}

fn hash_table_ref(hasher: &mut blake3::Hasher, reference: LocalCutTableRefV1) {
    hash_part(hasher, &reference.row_count().to_be_bytes());
    hash_optional_hash(hasher, reference.root_hash());
}
