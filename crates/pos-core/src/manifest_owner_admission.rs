//! Owner-verified scoped manifest admission and its atomic persistence port.
//!
//! The records in `manifest_owner_link` are portable structures. This module
//! binds a complete MCA1 catalog to every owned Timeline, its exact scoped
//! MSB1/WCS1 pair, signed MSR1, the Required EOP1/OPC1 WAL1 leaves and
//! native bytes, and the ADR-081 Revision 2 scope members: the recorded
//! RLS1/RTP1 lease, retained native member leaves and unavailable reference
//! leaves. A decoded or prepared batch is still not a Replay capability.

use std::collections::HashSet;

use crate::manifest_owner_members::{
    validate_scope_budgets, validate_scope_members, verify_member_classes,
    ManifestOwnerClassifiedLeafV1, ManifestOwnerScopeMembersV1,
};
use crate::output_policy::OutputPolicyV1;
use crate::{
    ArtifactOptionalityV1, Hash, ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1,
    ManifestSlotAdmissionReceiptInputV1, ManifestSlotAdmissionReceiptV1,
    ManifestSlotBindingInputV1, ManifestSlotBindingRowV1, ManifestSlotBindingV1, PluginId,
    TimelineId, WorldArtifactKindV1, WorldArtifactLeafV1, WorldClosureReadLimitsV1,
    WorldConsumerSetV1,
};

/// Maximum owned Timeline scopes committed by one admission transaction.
pub const MAX_MANIFEST_OWNER_ADMISSION_SCOPES_V1: usize = 1_048_576;
/// Whole native EOP1/OPC1 copy bound for this owner-admission slice.
pub const MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1: usize = 16_777_216;
/// Aggregate EOP1/OPC1 native-byte bound for one owner admission transaction.
pub const MAX_MANIFEST_OWNER_ADMISSION_NATIVE_BYTES_V1: usize =
    2 * MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1;
/// Exact OPC1 framing member count.
pub const OUTPUT_POLICY_CLOSURE_MEMBER_COUNT_V1: usize = 6;

/// Closed failures returned while decoding one bounded OPC1 envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OutputPolicyClosureEnvelopeErrorV1 {
    /// The envelope is malformed, truncated, has extra bytes, or binds another EOP1.
    #[error("invalid OPC1 envelope")]
    InvalidEnvelope,
    /// The exact envelope exceeds its accepted native-copy bound.
    #[error("OPC1 envelope exceeds its accepted bound")]
    BoundExceeded,
}

/// Borrowed native members from one exactly framed OPC1 closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputPolicyClosureEnvelopeV1<'a> {
    members: [&'a [u8]; OUTPUT_POLICY_CLOSURE_MEMBER_COUNT_V1],
}

impl<'a> OutputPolicyClosureEnvelopeV1<'a> {
    /// Decode bounded OPC1 framing and require member zero to equal exact EOP1 bytes.
    ///
    /// This shared core decoder owns only the OPC1 envelope contract. Runtime
    /// code remains responsible for validating each native member's schema.
    ///
    /// # Errors
    /// Returns `BoundExceeded` for oversized input and `InvalidEnvelope` for
    /// malformed framing, trailing bytes, or an EOP1 binding mismatch.
    pub fn from_canonical_bytes_v1(
        bytes: &'a [u8],
        expected_eop1: &[u8],
    ) -> Result<Self, OutputPolicyClosureEnvelopeErrorV1> {
        if bytes.len() > MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1 {
            return Err(OutputPolicyClosureEnvelopeErrorV1::BoundExceeded);
        }
        if bytes.get(..4) != Some(b"OPC1") {
            return Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope);
        }

        let mut members = [&[][..]; OUTPUT_POLICY_CLOSURE_MEMBER_COUNT_V1];
        let mut offset = 4_usize;
        for member in &mut members {
            let length_end = offset
                .checked_add(8)
                .ok_or(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)?;
            let length_bytes = bytes
                .get(offset..length_end)
                .ok_or(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)?;
            let mut raw_length = [0_u8; 8];
            raw_length.copy_from_slice(length_bytes);
            let length = usize::try_from(u64::from_be_bytes(raw_length))
                .map_err(|_| OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)?;
            let member_end = length_end
                .checked_add(length)
                .ok_or(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)?;
            *member = bytes
                .get(length_end..member_end)
                .ok_or(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope)?;
            offset = member_end;
        }
        if offset != bytes.len() || members[0] != expected_eop1 {
            return Err(OutputPolicyClosureEnvelopeErrorV1::InvalidEnvelope);
        }
        Ok(Self { members })
    }

    /// Borrow the exact EOP1 bytes in member zero.
    #[must_use]
    pub const fn eop1_bytes(&self) -> &'a [u8] {
        self.members[0]
    }

    /// Borrow the exact executable-budget bytes in member one.
    #[must_use]
    pub const fn executable_budget_bytes(&self) -> &'a [u8] {
        self.members[1]
    }

    /// Borrow the exact implementation artifact bytes in member two.
    #[must_use]
    pub const fn implementation_artifact(&self) -> &'a [u8] {
        self.members[2]
    }

    /// Borrow the exact configuration artifact bytes in member three.
    #[must_use]
    pub const fn configuration_artifact(&self) -> &'a [u8] {
        self.members[3]
    }

    /// Borrow the exact execution-profile artifact bytes in member four.
    #[must_use]
    pub const fn execution_profile_artifact(&self) -> &'a [u8] {
        self.members[4]
    }

    /// Borrow the exact retention-policy artifact bytes in member five.
    #[must_use]
    pub const fn retention_policy_artifact(&self) -> &'a [u8] {
        self.members[5]
    }
}

/// Closed preparation, verification and persistence failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestOwnerAdmissionErrorV1 {
    /// The requested transaction is outside the bounded native profile.
    #[error("manifest owner admission exceeds its accepted bounds")]
    BoundExceeded,
    /// The complete composition, scope, policy copy, binding, or receipt differs.
    #[error("manifest owner admission records do not form one exact complete batch")]
    InvalidBatch,
    /// The installed local owner rejected the registry or coordinator evidence.
    #[error("installed local owner rejected manifest admission evidence")]
    OwnerRejected,
    /// Owner state or an immutable historical row conflicts with this transaction.
    #[error("manifest owner admission conflicts with persisted state")]
    Conflict,
    /// A persisted owner row failed canonical-byte or identity validation.
    #[error("manifest owner admission storage contains a corrupt row")]
    CorruptState,
    /// Storage failed before a result could be determined.
    #[error("manifest owner admission storage outcome is unavailable")]
    StorageFailure,
}

/// Trusted local-owner checks performed before an admission is staged.
///
/// Applications must only use an implementation bound to the actual local
/// Plugin registry and installed coordinator-key verifier. An untrusted
/// remote caller's implementation is not an owner authority.
pub trait ManifestOwnerAdmissionVerifierV1: Send + Sync {
    /// Confirm that MCA1 is the exact current, complete registry-issued batch.
    ///
    /// # Errors
    /// Returns `OwnerRejected` when any `PluginId`, stable slot, pin, policy,
    /// closure, or registry revision is absent, changed, or unverified.
    fn verify_complete_composition(
        &self,
        catalog: &ManifestAdmissionCatalogV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1>;

    /// Confirm that these scopes are the complete resulting owner Timeline
    /// set and each WCS1 belongs to its independently retained RLS1 context.
    ///
    /// # Errors
    /// Returns `OwnerRejected` for an omitted, extra, stale, wrong-owner, or
    /// unauthenticated Timeline/scope/consumer-selector row.
    fn verify_complete_owned_scope_set(
        &self,
        owner_id: [u8; 32],
        timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
    ) -> Result<(), ManifestOwnerAdmissionErrorV1>;

    /// Confirm the installed coordinator key evidence and exact MSR1 signature.
    ///
    /// # Errors
    /// Returns `OwnerRejected` for an unknown, inactive, mismatched, or
    /// unauthorized coordinator identity or invalid signature.
    fn verify_coordinator_receipt(
        &self,
        receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1>;

    /// Confirm owner pre-state, operation allocation, and inventory successor.
    ///
    /// # Errors
    /// Returns `OwnerRejected` when the operation or inventory generation was
    /// not allocated from the actual local owner state.
    fn verify_owner_prestate_and_allocation(
        &self,
        request: &ManifestOwnerAdmissionRequestV1,
        current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1>;

    /// Sign one exact MSR1 draft with the installed coordinator admission role.
    ///
    /// The implementation selects its own retained coordinator evidence and
    /// must verify that evidence and signature before returning. The draft
    /// contains no caller-supplied key evidence, signature, or signer.
    ///
    /// # Errors
    /// Returns `OwnerRejected` when the installed role or key is unavailable,
    /// mismatched, inactive, or cannot sign this owner's receipt.
    fn sign_coordinator_receipt(
        &self,
        draft: ManifestSlotAdmissionReceiptDraftV1,
    ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1>;

    /// Confirm exact native owner/copy policy for one scoped EOP1/OPC1 pair.
    ///
    /// # Errors
    /// Returns `OwnerRejected` when purpose, lease, owner, key dependencies,
    /// retention class, or native closure extraction is not installed.
    fn verify_native_policy_copies(
        &self,
        timeline_id: TimelineId,
        scope: Hash,
        copies: &ManifestOwnerPolicyCopiesV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1>;

    /// Classify every member and reference leaf of one owned Timeline scope.
    ///
    /// Called once per scope after its per-Plugin
    /// [`Self::verify_native_policy_copies`] calls. The installed owner policy
    /// hook returns the data class, transition and key dependencies of each
    /// leaf in `members.leaves` order; the owner never guesses them.
    ///
    /// # Errors
    /// Returns `OwnerRejected` when the scope's members cannot be classified
    /// under the installed owner and purpose policy.
    fn classify_scope_member_leaves(
        &self,
        timeline_id: TimelineId,
        scope: Hash,
        members: &ManifestOwnerScopeMembersV1,
    ) -> Result<Vec<ManifestOwnerClassifiedLeafV1>, ManifestOwnerAdmissionErrorV1>;
}

/// Exact Required native bytes and WAL1 leaves for one admitted Plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerPolicyCopiesV1 {
    /// Plugin identity from the complete MCA1 catalog.
    pub plugin_id: PluginId,
    /// Exact canonical EOP1 bytes.
    pub eop1_bytes: Vec<u8>,
    /// Required scoped kind-0 WAL1 leaf for EOP1.
    pub eop1_leaf: WorldArtifactLeafV1,
    /// Exact canonical OPC1 bytes.
    pub opc1_bytes: Vec<u8>,
    /// Required scoped kind-14 WAL1 leaf for OPC1.
    pub opc1_leaf: WorldArtifactLeafV1,
}

/// One complete Timeline scope in the resulting owned set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerTimelineAdmissionV1 {
    /// Owned Timeline identity; the list is complete for this owner generation.
    pub timeline_id: TimelineId,
    /// Exact ADR-081 Timeline/RLS1 scope.
    pub scope: Hash,
    /// Separately authenticated consumer and producer selector.
    pub wcs1: WorldConsumerSetV1,
    /// Exact MSB1 rows for the complete MCA1 set.
    pub binding: ManifestSlotBindingV1,
    /// Installed-coordinator-signed receipt for this scope.
    pub receipt: ManifestSlotAdmissionReceiptV1,
    /// Exact native policy bytes and Required leaves, sorted by `PluginId`.
    pub policy_copies: Vec<ManifestOwnerPolicyCopiesV1>,
    /// Recorded RLS1/RTP1 lease and the scope's member and reference leaves.
    pub members: ManifestOwnerScopeMembersV1,
}

/// Untrusted per-Timeline request; the owner derives MSB1 and signs MSR1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerTimelineAdmissionRequestV1 {
    /// Owned Timeline identity.
    pub timeline_id: TimelineId,
    /// Exact ADR-081 Timeline/RLS1 scope.
    pub scope: Hash,
    /// Separately authenticated consumer and producer selector.
    pub wcs1: WorldConsumerSetV1,
    /// Exact native policy bytes and Required leaves, sorted by `PluginId`.
    pub policy_copies: Vec<ManifestOwnerPolicyCopiesV1>,
    /// Recorded RLS1/RTP1 lease and the scope's member and reference leaves.
    pub members: ManifestOwnerScopeMembersV1,
}

/// First twelve MSR1 fields that the installed coordinator signs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestSlotAdmissionReceiptDraftV1 {
    /// Exact owner identity.
    pub owner_id: [u8; 32],
    /// Resulting checked owner configuration generation.
    pub configuration_generation: u64,
    /// Exact ADR-081 Timeline/RLS1 scope.
    pub scope: Hash,
    /// Selected WCS1 content address.
    pub wcs1_hash: Hash,
    /// Immutable complete MCA1 identity.
    pub mca1_hash: Hash,
    /// Owner-allocated idempotency operation.
    pub admission_operation_id: Hash,
    /// Exact pre-admission visible LCQ1, absent only before first visibility.
    pub previous_visible_lcq1_hash: Option<Hash>,
    /// Exact pre-admission inventory CAS generation.
    pub expected_inventory_generation: Option<Hash>,
    /// Complete scoped MSB1 identity.
    pub msb1_hash: Hash,
}

impl ManifestSlotAdmissionReceiptDraftV1 {
    /// Construct the exact MSR1 value to be signed using installed evidence.
    ///
    /// # Errors
    /// Returns an error if the combined receipt fields violate MSR1 invariants.
    pub fn with_evidence_and_signature(
        self,
        coordinator_key_evidence_hash: Hash,
        signature: [u8; 64],
    ) -> Result<ManifestSlotAdmissionReceiptV1, crate::ManifestOwnerLinkErrorV1> {
        ManifestSlotAdmissionReceiptV1::new(ManifestSlotAdmissionReceiptInputV1 {
            owner_id: self.owner_id,
            configuration_generation: self.configuration_generation,
            scope: self.scope,
            wcs1_hash: self.wcs1_hash,
            mca1_hash: self.mca1_hash,
            admission_operation_id: self.admission_operation_id,
            previous_visible_lcq1_hash: self.previous_visible_lcq1_hash,
            expected_inventory_generation: self.expected_inventory_generation,
            msb1_hash: self.msb1_hash,
            coordinator_key_evidence_hash,
            signature,
        })
    }
}

/// One untrusted request for an atomic owner admission transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerAdmissionInputV1 {
    /// Nonzero idempotency identity allocated by the local owner.
    pub operation_id: Hash,
    /// Exact immutable complete Plugin catalog for the resulting generation.
    pub catalog: ManifestAdmissionCatalogV1,
    /// Current configuration generation; `None` is absent-owner genesis.
    pub expected_configuration_generation: Option<u64>,
    /// Last visible LCQ1 before this transaction, null only before first visibility.
    pub previous_visible_lcq1_hash: Option<Hash>,
    /// Actual current inventory generation; null only for absent-owner genesis.
    pub expected_inventory_generation: Option<Hash>,
    /// New opaque inventory generation allocated for the committed successor.
    pub resulting_inventory_generation: Hash,
    /// Recorded WCB1 read limits for the resulting configuration generation.
    pub read_limits: WorldClosureReadLimitsV1,
    /// Complete resulting owned Timeline set, never a partial delta.
    pub timelines: Vec<ManifestOwnerTimelineAdmissionV1>,
}

/// Untrusted owner admission request before receipt signing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerAdmissionRequestV1 {
    /// Nonzero idempotency identity allocated by the local owner.
    pub operation_id: Hash,
    /// Exact immutable complete Plugin catalog for the resulting generation.
    pub catalog: ManifestAdmissionCatalogV1,
    /// Current configuration generation; `None` is absent-owner genesis.
    pub expected_configuration_generation: Option<u64>,
    /// Last visible LCQ1 before this transaction, null only before first visibility.
    pub previous_visible_lcq1_hash: Option<Hash>,
    /// Actual current inventory generation; null only for absent-owner genesis.
    pub expected_inventory_generation: Option<Hash>,
    /// New opaque owner-allocated inventory generation.
    pub resulting_inventory_generation: Hash,
    /// WCB1 read limits recorded for the resulting configuration generation.
    pub read_limits: WorldClosureReadLimitsV1,
    /// Complete resulting owned Timeline set, never a partial delta.
    pub timelines: Vec<ManifestOwnerTimelineAdmissionRequestV1>,
}

/// Return the stable digest of the unsigned admission input used for retries.
///
/// The digest excludes MSR1 signatures and coordinator evidence. It lets the
/// owner resolve a committed operation before invoking the installed signer.
///
/// # Errors
/// Returns a shape or bound error before hashing an invalid request.
pub fn manifest_owner_admission_intent_digest_v1(
    request: &ManifestOwnerAdmissionRequestV1,
) -> Result<Hash, ManifestOwnerAdmissionErrorV1> {
    validate_admission_request(request)?;
    Ok(digest_request(request))
}

/// Complete, owner-verified batch that a store may commit atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedManifestOwnerAdmissionV1 {
    input: ManifestOwnerAdmissionInputV1,
    intent_digest: Hash,
}

impl PreparedManifestOwnerAdmissionV1 {
    /// Borrow the complete verified request for a same-store transaction.
    #[must_use]
    pub const fn input(&self) -> &ManifestOwnerAdmissionInputV1 {
        &self.input
    }

    /// Return the digest of the unsigned operation input.
    #[must_use]
    pub const fn intent_digest(&self) -> Hash {
        self.intent_digest
    }
}

/// Verify the complete batch, derive scoped MSB1 records, and sign every MSR1
/// with the installed coordinator before staging.
///
/// # Errors
/// Rejects partial/duplicate scopes, catalog mismatch, invalid CAS null-state,
/// missing zero-output copies, malformed EOP1/OPC1 identities, invalid read
/// limits, a lease, scope, member leaf or edge that differs from the exact
/// derivation of its native bytes (`InvalidBatch`), retained native bytes
/// above the recorded `max_native_bytes` (`BoundExceeded`), or an owner
/// verifier rejection. No signature supplied by the request is treated as
/// authority without the installed verifier.
pub fn prepare_manifest_owner_admission_v1(
    request: ManifestOwnerAdmissionRequestV1,
    verifier: &dyn ManifestOwnerAdmissionVerifierV1,
    current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
) -> Result<PreparedManifestOwnerAdmissionV1, ManifestOwnerAdmissionErrorV1> {
    validate_admission_request(&request)?;
    validate_current_prestate(&request, current_state)?;
    let intent_digest = digest_request(&request);
    verifier.verify_complete_composition(&request.catalog)?;
    verifier.verify_owner_prestate_and_allocation(&request, current_state)?;
    verifier
        .verify_complete_owned_scope_set(request.catalog.as_input().owner_id, &request.timelines)?;

    let timelines = request
        .timelines
        .iter()
        .map(|timeline_request| prepare_timeline(&request, timeline_request, verifier))
        .collect::<Result<Vec<_>, _>>()?;

    let input = ManifestOwnerAdmissionInputV1 {
        operation_id: request.operation_id,
        catalog: request.catalog,
        expected_configuration_generation: request.expected_configuration_generation,
        previous_visible_lcq1_hash: request.previous_visible_lcq1_hash,
        expected_inventory_generation: request.expected_inventory_generation,
        resulting_inventory_generation: request.resulting_inventory_generation,
        read_limits: request.read_limits,
        timelines,
    };
    validate_transaction_shape(&input)?;
    for timeline in &input.timelines {
        validate_timeline_admission(&input, timeline)?;
    }
    Ok(PreparedManifestOwnerAdmissionV1 {
        input,
        intent_digest,
    })
}

/// Verify one scope, derive its MSB1, and sign its MSR1 with the installed
/// coordinator after the owner hook classified every member leaf.
fn prepare_timeline(
    request: &ManifestOwnerAdmissionRequestV1,
    timeline_request: &ManifestOwnerTimelineAdmissionRequestV1,
    verifier: &dyn ManifestOwnerAdmissionVerifierV1,
) -> Result<ManifestOwnerTimelineAdmissionV1, ManifestOwnerAdmissionErrorV1> {
    validate_timeline_request(&request.catalog, timeline_request)?;
    let binding = derive_binding(&request.catalog, timeline_request)?;
    for copies in &timeline_request.policy_copies {
        verifier.verify_native_policy_copies(
            timeline_request.timeline_id,
            timeline_request.scope,
            copies,
        )?;
    }
    let classes = verifier.classify_scope_member_leaves(
        timeline_request.timeline_id,
        timeline_request.scope,
        &timeline_request.members,
    )?;
    verify_member_classes(&timeline_request.members, &classes)?;
    let draft = ManifestSlotAdmissionReceiptDraftV1 {
        owner_id: request.catalog.as_input().owner_id,
        configuration_generation: request.catalog.as_input().configuration_generation,
        scope: timeline_request.scope,
        wcs1_hash: timeline_request.wcs1.digest(),
        mca1_hash: request.catalog.digest(),
        admission_operation_id: request.operation_id,
        previous_visible_lcq1_hash: request.previous_visible_lcq1_hash,
        expected_inventory_generation: request.expected_inventory_generation,
        msb1_hash: binding.digest(),
    };
    let receipt = verifier.sign_coordinator_receipt(draft)?;
    if !receipt_matches_draft(&receipt, &draft) {
        return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
    }
    verifier.verify_coordinator_receipt(&receipt)?;
    Ok(ManifestOwnerTimelineAdmissionV1 {
        timeline_id: timeline_request.timeline_id,
        scope: timeline_request.scope,
        wcs1: timeline_request.wcs1.clone(),
        binding,
        receipt,
        policy_copies: timeline_request.policy_copies.clone(),
        members: timeline_request.members.clone(),
    })
}

/// Recheck the self-contained identities of one persisted historical row.
///
/// This is a structural integrity check; it does not reauthenticate the
/// registry, signer, current retention authority, or current protected use.
///
/// # Errors
/// Returns `CorruptState` when its retained MCA1/MSB1/MSR1/WCS1 or native
/// policy bytes do not agree exactly.
pub fn validate_manifest_owner_admission_snapshot_v1(
    snapshot: &ManifestOwnerAdmissionSnapshotV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let generation = snapshot.catalog.as_input().configuration_generation;
    let (expected_configuration_generation, previous_visible_lcq1_hash) = if generation == 1 {
        (None, None)
    } else {
        (
            Some(generation - 1),
            snapshot
                .timeline
                .receipt
                .as_input()
                .previous_visible_lcq1_hash,
        )
    };
    let input = ManifestOwnerAdmissionInputV1 {
        operation_id: snapshot.operation_id,
        catalog: snapshot.catalog.clone(),
        expected_configuration_generation,
        previous_visible_lcq1_hash,
        expected_inventory_generation: snapshot.expected_inventory_generation,
        resulting_inventory_generation: snapshot.resulting_inventory_generation,
        read_limits: snapshot.read_limits,
        timelines: vec![snapshot.timeline.clone()],
    };
    validate_transaction_shape(&input)
        .and_then(|()| validate_timeline_admission(&input, &snapshot.timeline))
        .and_then(|()| {
            validate_scope_budgets(
                snapshot.read_limits,
                [(
                    snapshot.timeline.policy_copies.as_slice(),
                    &snapshot.timeline.members,
                )],
            )
        })
}

/// Whether the atomic owner transaction applied or recovered an exact retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestOwnerAdmissionCommitKindV1 {
    /// The complete new generation and all per-Timeline rows became visible.
    Applied,
    /// The operation id and complete input match an earlier committed result.
    ExactRetry,
}

/// Durable transaction result, retained for idempotent operation recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerAdmissionCommitV1 {
    /// Whether this call applied new rows or resolved its exact prior result.
    pub kind: ManifestOwnerAdmissionCommitKindV1,
    /// Configuration generation committed by this operation.
    pub configuration_generation: u64,
    /// Exact resulting opaque owner inventory generation.
    pub inventory_generation: Hash,
    /// Scope-ordered immutable MSR1 content addresses.
    pub receipt_hashes: Vec<Hash>,
}

/// Native owner admission snapshot retained for historical readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerAdmissionSnapshotV1 {
    /// Exact immutable MCA1 row for this historical generation.
    pub catalog: ManifestAdmissionCatalogV1,
    /// One exact Timeline/WCS1/MSB1/MSR1 and native-copy set.
    pub timeline: ManifestOwnerTimelineAdmissionV1,
    /// The operation that published this complete generation.
    pub operation_id: Hash,
    /// Inventory generation observed before staging, if one existed.
    pub expected_inventory_generation: Option<Hash>,
    /// Inventory generation committed with this row.
    pub resulting_inventory_generation: Hash,
    /// WCB1 read limits recorded for this configuration generation.
    pub read_limits: WorldClosureReadLimitsV1,
}

/// Current owner state required to form the next generation's CAS request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerAdmissionOwnerStateV1 {
    /// Exact owner identity.
    pub owner_id: [u8; 32],
    /// Current immutable catalog generation.
    pub configuration_generation: u64,
    /// Last visible receipt, null only before the first visible cut.
    pub previous_visible_lcq1_hash: Option<Hash>,
    /// Actual inventory generation used by the next admission CAS.
    pub inventory_generation: Hash,
    /// Complete currently owned Timeline roster.
    pub timelines: Vec<TimelineId>,
}

/// Same-store persistence boundary for owner state and historical admissions.
pub trait ManifestOwnerAdmissionPersistencePortV1 {
    /// Load the current owner CAS values and its complete owned Timeline roster.
    ///
    /// # Errors
    /// Returns `CorruptState` when the state row and complete admission rows
    /// disagree, or `StorageFailure` when the backend cannot read them.
    fn read_manifest_owner_state_v1(
        &self,
        owner_id: [u8; 32],
    ) -> Result<Option<ManifestOwnerAdmissionOwnerStateV1>, ManifestOwnerAdmissionErrorV1>;

    /// Resolve a prior operation before the installed coordinator signs again.
    ///
    /// An identical unsigned input returns the original result with
    /// `ExactRetry`; reuse of the operation ID for another input returns
    /// `Conflict`. A missing operation returns `None`.
    ///
    /// # Errors
    /// Returns `Conflict` when an operation ID is reused for another intent,
    /// `CorruptState` when its persisted row is invalid, or `StorageFailure`
    /// when the lookup cannot be completed.
    fn resolve_manifest_owner_admission_retry_v1(
        &self,
        owner_id: [u8; 32],
        operation_id: Hash,
        intent_digest: Hash,
    ) -> Result<Option<ManifestOwnerAdmissionCommitV1>, ManifestOwnerAdmissionErrorV1>;

    /// Atomically CAS and commit the complete owner generation.
    ///
    /// A store validates the exact current owner/configuration/inventory
    /// pre-state, resolves identical operation retries, rejects operation-id
    /// reuse with different input, and publishes the entire successor only
    /// after every Timeline/catalog/binding/receipt/copy row is ready. In the
    /// same transaction it records the generation's read limits and each
    /// scope's lease and member leaves by `(scope, kind, native digest)`: an
    /// identical member registration deduplicates, any other one conflicts.
    /// A Timeline whose latest recorded lease is extended by the replacement
    /// lease is rejected, as decided by
    /// [`crate::validate_manifest_owner_lease_replacement_v1`].
    ///
    /// # Errors
    /// Returns `OwnerRejected` for a lease extension, otherwise `Conflict`,
    /// `CorruptState`, or `StorageFailure`; failure leaves no partial
    /// generation or visible receipt. `Conflict` is the intended error for a
    /// member leaf that differs from one an earlier transaction persisted
    /// under the same key; request-shape faults never reach the store and are
    /// rejected as `InvalidBatch` during preparation.
    fn commit_manifest_owner_admission_v1(
        &mut self,
        batch: PreparedManifestOwnerAdmissionV1,
    ) -> Result<ManifestOwnerAdmissionCommitV1, ManifestOwnerAdmissionErrorV1>;

    /// Read one immutable historical scoped admission and its exact native bytes.
    ///
    /// # Errors
    /// Returns `CorruptState` if any exact persisted identity or byte check fails.
    fn read_manifest_owner_admission_v1(
        &self,
        owner_id: [u8; 32],
        configuration_generation: u64,
        timeline_id: TimelineId,
    ) -> Result<Option<ManifestOwnerAdmissionSnapshotV1>, ManifestOwnerAdmissionErrorV1>;
}

fn validate_transaction_shape(
    input: &ManifestOwnerAdmissionInputV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let owner_id = input.catalog.as_input().owner_id;
    let generation = input.catalog.as_input().configuration_generation;
    if input.operation_id == Hash::zero()
        || input.resulting_inventory_generation == Hash::zero()
        || input.timelines.is_empty()
        || input.timelines.len() > MAX_MANIFEST_OWNER_ADMISSION_SCOPES_V1
    {
        return Err(ManifestOwnerAdmissionErrorV1::BoundExceeded);
    }
    validate_native_copy_aggregate(
        input
            .timelines
            .iter()
            .map(|timeline| timeline.policy_copies.as_slice()),
    )?;
    if input.expected_inventory_generation == Some(Hash::zero())
        || input.previous_visible_lcq1_hash == Some(Hash::zero())
        || input
            .expected_inventory_generation
            .is_some_and(|expected| expected == input.resulting_inventory_generation)
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    match input.expected_configuration_generation {
        None => {
            if generation != 1
                || input.previous_visible_lcq1_hash.is_some()
                || input.expected_inventory_generation.is_some()
            {
                return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
            }
        }
        Some(current) => {
            if current == 0
                || current.checked_add(1) != Some(generation)
                || input.expected_inventory_generation.is_none()
            {
                return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
            }
        }
    }

    let mut timelines = HashSet::with_capacity(input.timelines.len());
    let mut scopes = HashSet::with_capacity(input.timelines.len());
    if input
        .timelines
        .windows(2)
        .any(|pair| pair[0].timeline_id >= pair[1].timeline_id)
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    for timeline in &input.timelines {
        if !timelines.insert(timeline.timeline_id)
            || !scopes.insert(timeline.scope)
            || timeline.scope == Hash::zero()
            || timeline.wcs1.producers().is_empty()
            || timeline.policy_copies.len() > input.catalog.as_input().rows.len()
        {
            return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
        }
        if timeline.wcs1.scope() == Hash::zero() || timeline.wcs1.scope() != timeline.scope {
            return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
        }
    }
    if owner_id == [0; 32] {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    Ok(())
}

fn validate_admission_request(
    request: &ManifestOwnerAdmissionRequestV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    validate_request_shape(request).and_then(|()| {
        validate_scope_budgets(
            request.read_limits,
            request
                .timelines
                .iter()
                .map(|timeline| (timeline.policy_copies.as_slice(), &timeline.members)),
        )
    })
}

fn validate_request_shape(
    request: &ManifestOwnerAdmissionRequestV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let owner_id = request.catalog.as_input().owner_id;
    let generation = request.catalog.as_input().configuration_generation;
    if request.operation_id == Hash::zero()
        || request.resulting_inventory_generation == Hash::zero()
        || request.timelines.is_empty()
        || request.timelines.len() > MAX_MANIFEST_OWNER_ADMISSION_SCOPES_V1
        || owner_id == [0; 32]
    {
        return Err(ManifestOwnerAdmissionErrorV1::BoundExceeded);
    }
    if request.expected_inventory_generation == Some(Hash::zero())
        || request.previous_visible_lcq1_hash == Some(Hash::zero())
        || request
            .expected_inventory_generation
            .is_some_and(|expected| expected == request.resulting_inventory_generation)
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    validate_native_copy_aggregate(
        request
            .timelines
            .iter()
            .map(|timeline| timeline.policy_copies.as_slice()),
    )?;
    match request.expected_configuration_generation {
        None => {
            if generation != 1
                || request.previous_visible_lcq1_hash.is_some()
                || request.expected_inventory_generation.is_some()
            {
                return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
            }
        }
        Some(current) => {
            if current == 0
                || current.checked_add(1) != Some(generation)
                || request.expected_inventory_generation.is_none()
            {
                return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
            }
        }
    }
    if request
        .timelines
        .windows(2)
        .any(|pair| pair[0].timeline_id >= pair[1].timeline_id)
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    let mut scopes = HashSet::with_capacity(request.timelines.len());
    for timeline in &request.timelines {
        if timeline.scope == Hash::zero() || !scopes.insert(timeline.scope) {
            return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
        }
    }
    Ok(())
}

fn validate_native_copy_aggregate<'a>(
    copy_batches: impl IntoIterator<Item = &'a [ManifestOwnerPolicyCopiesV1]>,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let mut aggregate_bytes = 0_usize;
    for copies in copy_batches {
        for copy in copies {
            if copy.eop1_bytes.len() > MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1
                || copy.opc1_bytes.len() > MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1
            {
                return Err(ManifestOwnerAdmissionErrorV1::BoundExceeded);
            }
            let copy_bytes = copy.eop1_bytes.len().saturating_add(copy.opc1_bytes.len());
            aggregate_bytes = aggregate_bytes.saturating_add(copy_bytes);
            if aggregate_bytes > MAX_MANIFEST_OWNER_ADMISSION_NATIVE_BYTES_V1 {
                return Err(ManifestOwnerAdmissionErrorV1::BoundExceeded);
            }
        }
    }
    Ok(())
}

fn validate_current_prestate(
    request: &ManifestOwnerAdmissionRequestV1,
    current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let owner_id = request.catalog.as_input().owner_id;
    match (request.expected_configuration_generation, current_state) {
        (None, None) => Ok(()),
        (Some(expected_generation), Some(state))
            if state.owner_id == owner_id
                && state.configuration_generation == expected_generation
                && state.previous_visible_lcq1_hash == request.previous_visible_lcq1_hash
                && Some(state.inventory_generation) == request.expected_inventory_generation
                && !state.timelines.is_empty()
                && expected_generation.checked_add(1)
                    == Some(request.catalog.as_input().configuration_generation) =>
        {
            Ok(())
        }
        _ => Err(ManifestOwnerAdmissionErrorV1::Conflict),
    }
}

fn validate_timeline_request(
    catalog: &ManifestAdmissionCatalogV1,
    timeline: &ManifestOwnerTimelineAdmissionRequestV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    validate_timeline_policy_copies(
        catalog,
        timeline.scope,
        &timeline.wcs1,
        &timeline.policy_copies,
        None,
    )
    .and_then(|()| {
        validate_scope_members(
            catalog.as_input().owner_id,
            timeline.timeline_id,
            &timeline.wcs1,
            &timeline.policy_copies,
            &timeline.members,
        )
    })
}

fn derive_binding(
    catalog: &ManifestAdmissionCatalogV1,
    timeline: &ManifestOwnerTimelineAdmissionRequestV1,
) -> Result<ManifestSlotBindingV1, ManifestOwnerAdmissionErrorV1> {
    let rows = catalog
        .as_input()
        .rows
        .iter()
        .map(|row| {
            let copy = timeline
                .policy_copies
                .iter()
                .find(|copy| copy.plugin_id == row.plugin_id)
                .ok_or(ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
            Ok(ManifestSlotBindingRowV1 {
                stable_slot: row.stable_slot.clone(),
                plugin_id: row.plugin_id,
                eop1_wal1_hash: copy.eop1_leaf.digest(),
                closure_hash: row.closure_hash,
            })
        })
        .collect::<Result<Vec<_>, ManifestOwnerAdmissionErrorV1>>()?;
    ManifestSlotBindingV1::new(ManifestSlotBindingInputV1 {
        scope: timeline.scope,
        wcs1_hash: timeline.wcs1.digest(),
        rows,
    })
    .map_err(|_| ManifestOwnerAdmissionErrorV1::InvalidBatch)
}

fn receipt_matches_draft(
    receipt: &ManifestSlotAdmissionReceiptV1,
    draft: &ManifestSlotAdmissionReceiptDraftV1,
) -> bool {
    let fields = receipt.as_input();
    fields.owner_id == draft.owner_id
        && fields.configuration_generation == draft.configuration_generation
        && fields.scope == draft.scope
        && fields.wcs1_hash == draft.wcs1_hash
        && fields.mca1_hash == draft.mca1_hash
        && fields.admission_operation_id == draft.admission_operation_id
        && fields.previous_visible_lcq1_hash == draft.previous_visible_lcq1_hash
        && fields.expected_inventory_generation == draft.expected_inventory_generation
        && fields.msb1_hash == draft.msb1_hash
        && fields.coordinator_key_evidence_hash != Hash::zero()
        && fields.signature != [0; 64]
}

fn validate_timeline_admission(
    input: &ManifestOwnerAdmissionInputV1,
    timeline: &ManifestOwnerTimelineAdmissionV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let catalog = input.catalog.as_input();
    let binding = timeline.binding.as_input();
    let receipt = timeline.receipt.as_input();
    if binding.scope != timeline.scope
        || binding.wcs1_hash != timeline.wcs1.digest()
        || binding.rows.len() != catalog.rows.len()
        || receipt.owner_id != catalog.owner_id
        || receipt.configuration_generation != catalog.configuration_generation
        || receipt.scope != timeline.scope
        || receipt.wcs1_hash != timeline.wcs1.digest()
        || receipt.mca1_hash != input.catalog.digest()
        || receipt.admission_operation_id != input.operation_id
        || receipt.previous_visible_lcq1_hash != input.previous_visible_lcq1_hash
        || receipt.expected_inventory_generation != input.expected_inventory_generation
        || receipt.msb1_hash != timeline.binding.digest()
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    validate_timeline_policy_copies(
        &input.catalog,
        timeline.scope,
        &timeline.wcs1,
        &timeline.policy_copies,
        Some(&timeline.binding),
    )
    .and_then(|()| {
        validate_scope_members(
            catalog.owner_id,
            timeline.timeline_id,
            &timeline.wcs1,
            &timeline.policy_copies,
            &timeline.members,
        )
    })
}

fn validate_timeline_policy_copies(
    catalog: &ManifestAdmissionCatalogV1,
    scope: Hash,
    wcs1: &WorldConsumerSetV1,
    policy_copies: &[ManifestOwnerPolicyCopiesV1],
    binding: Option<&ManifestSlotBindingV1>,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let catalog_input = catalog.as_input();
    if scope == Hash::zero()
        || wcs1.scope() != scope
        || wcs1.producers().is_empty()
        || policy_copies.len() != catalog_input.rows.len()
        || policy_copies
            .windows(2)
            .any(|pair| pair[0].plugin_id >= pair[1].plugin_id)
        || binding.is_some_and(|value| value.as_input().rows.len() != catalog_input.rows.len())
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }

    let mut copy_ids = HashSet::with_capacity(policy_copies.len());
    for copy in policy_copies {
        if !copy_ids.insert(copy.plugin_id) {
            return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
        }
        let row = catalog_input
            .rows
            .iter()
            .find(|row| row.plugin_id == copy.plugin_id)
            .ok_or(ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
        if !valid_native_copy(catalog_input.owner_id, scope, row, copy) {
            return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
        }
        if let Some(binding) = binding {
            let slot = binding
                .as_input()
                .rows
                .iter()
                .find(|binding_row| binding_row.plugin_id == row.plugin_id)
                .ok_or(ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
            if slot.stable_slot != row.stable_slot
                || slot.closure_hash != row.closure_hash
                || slot.eop1_wal1_hash != copy.eop1_leaf.digest()
            {
                return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
            }
        }
    }

    for producer in wcs1.producers() {
        let row = catalog_input
            .rows
            .iter()
            .find(|row| row.plugin_id == producer.plugin_id())
            .ok_or(ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
        if row.eop1_native_digest != producer.output_policy_hash() {
            return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
        }
    }
    Ok(())
}

fn valid_native_copy(
    owner_id: [u8; 32],
    scope: Hash,
    row: &ManifestAdmissionCatalogRowV1,
    copy: &ManifestOwnerPolicyCopiesV1,
) -> bool {
    let Ok(policy) = OutputPolicyV1::from_canonical_cbor(&copy.eop1_bytes) else {
        return false;
    };
    let eop = copy.eop1_leaf.as_input();
    let opc = copy.opc1_leaf.as_input();
    policy.fields().plugin_id == row.plugin_id
        && policy.fields().plugin_id == copy.plugin_id
        && policy.fields().plugin_version == row.plugin_version
        && policy.fields().implementation_hash == row.implementation_hash
        && policy.digest() == row.eop1_native_digest
        && OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(
            &copy.opc1_bytes,
            &copy.eop1_bytes,
        )
        .is_ok()
        && opc1_native_digest(&copy.opc1_bytes) == row.closure_hash
        && eop.scope == scope
        && opc.scope == scope
        && eop.kind == WorldArtifactKindV1::OutputPolicy
        && opc.kind == WorldArtifactKindV1::OutputPolicyClosure
        && eop.native_digest == row.eop1_native_digest
        && opc.native_digest == row.closure_hash
        && copy.eop1_bytes.len() as u64 == eop.native_byte_length
        && copy.opc1_bytes.len() as u64 == opc.native_byte_length
        && eop.owner == owner_id
        && opc.owner == owner_id
        && eop.optionality == ArtifactOptionalityV1::Required
        && opc.optionality == ArtifactOptionalityV1::Required
        && eop.source_lease_hash == opc.source_lease_hash
}

pub(crate) fn opc1_native_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn digest_request(request: &ManifestOwnerAdmissionRequestV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-owner-admission-intent.v1\0");
    hash_part(&mut hasher, request.operation_id.as_bytes());
    hash_part(&mut hasher, &request.catalog.to_canonical_cbor());
    if let Some(generation) = request.expected_configuration_generation {
        hasher.update(&[1]);
        hash_part(&mut hasher, &generation.to_be_bytes());
    } else {
        hasher.update(&[0]);
    }
    hash_optional_hash(&mut hasher, request.previous_visible_lcq1_hash);
    hash_optional_hash(&mut hasher, request.expected_inventory_generation);
    hash_part(
        &mut hasher,
        request.resulting_inventory_generation.as_bytes(),
    );
    hash_count(&mut hasher, request.timelines.len());
    for timeline in &request.timelines {
        hasher.update(b"timeline\0");
        hash_part(&mut hasher, &timeline.timeline_id.inner().to_bytes());
        hash_part(&mut hasher, timeline.scope.as_bytes());
        hash_part(&mut hasher, timeline.wcs1.encode().as_slice());
        hash_count(&mut hasher, timeline.policy_copies.len());
        for copies in &timeline.policy_copies {
            hasher.update(b"policy-copy\0");
            hash_part(&mut hasher, &copies.plugin_id.inner().to_bytes());
            hash_part(&mut hasher, &copies.eop1_bytes);
            hash_part(&mut hasher, &copies.eop1_leaf.to_canonical_cbor());
            hash_part(&mut hasher, &copies.opc1_bytes);
            hash_part(&mut hasher, &copies.opc1_leaf.to_canonical_cbor());
        }
        hash_scope_members(&mut hasher, &timeline.members);
    }
    hash_read_limits(&mut hasher, request.read_limits);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn hash_scope_members(hasher: &mut blake3::Hasher, members: &ManifestOwnerScopeMembersV1) {
    hasher.update(b"scope-members\0");
    hash_part(hasher, &members.rtp1_bytes);
    hash_part(hasher, &members.rls1_bytes);
    hash_count(hasher, members.leaves.len());
    for member in &members.leaves {
        hash_part(hasher, &member.leaf.to_canonical_cbor());
        hash_part(hasher, &member.native_bytes);
    }
}

fn hash_read_limits(hasher: &mut blake3::Hasher, limits: WorldClosureReadLimitsV1) {
    hasher.update(b"read-limits\0");
    hasher.update(&limits.max_node_visits.to_be_bytes());
    hasher.update(&limits.max_native_bytes.to_be_bytes());
    hasher.update(&[limits.max_combined_depth]);
}

fn hash_count(hasher: &mut blake3::Hasher, count: usize) {
    hasher.update(&(count as u64).to_be_bytes());
}

fn hash_optional_hash(hasher: &mut blake3::Hasher, value: Option<Hash>) {
    if let Some(value) = value {
        hasher.update(&[1]);
        hash_part(hasher, value.as_bytes());
    } else {
        hasher.update(&[0]);
    }
}

fn hash_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
