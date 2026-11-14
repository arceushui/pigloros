//! Canonical community lifecycle data records from ADR-124 and ADR-129.
//!
//! A decoded record proves only its wire shape and local field invariants.
//! The installed owner must independently authorize and authenticate its
//! source, selected generation, current head and actual protected use. These
//! codecs cannot issue a guest permit or restore a live state cell.

mod classification;
mod copy_inventory;
mod envelope;
mod error;
mod failure;
mod generation_admission;
mod graph_root;
mod guest_claim;
mod guest_error;
mod host_error;
mod initialization;
mod input_group;
mod input_reference;
mod invocation;
mod key_intent;
mod materialization;
mod member;
mod member_progress;
mod metadata_envelope;
mod metadata_scope;
mod native_node;
mod original_provenance;
mod owner_binding;
mod prepared;
mod profile;
mod progress;
mod protected_object;
mod quarantine;
mod quarantine_control;
mod recording;
mod reservation;
mod revision;
mod scope_binding;
mod seal;
mod selected_head;
mod selection;
mod source_closure;
mod state;
mod step;
mod terminal;

pub use classification::{
    CommunityArtifactChildrenV1, CommunityClassificationProofInputV1,
    CommunityClassificationProofV1,
};
pub use copy_inventory::{
    CommunityCopyHolderV1, CommunityCopyInventoryInputV1, CommunityCopyInventoryV1,
    CommunityCopyStateV1,
};
pub use envelope::{
    CommunityArtifactHeaderInputV1, CommunityArtifactHeaderV1, CommunityArtifactKindV1,
    CommunityArtifactOperationV1, CommunityArtifactPurposeV1, CommunityEncryptedEnvelopeV1,
    MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1,
};
pub use error::CommunityLifecycleErrorV1;
pub use failure::{
    CommunityInvocationFailureInputV1, CommunityInvocationFailureV1, CommunityPassFailureInputV1,
    CommunityPassFailureV1,
};
pub use generation_admission::{
    CommunityGenerationAdmissionInputV1, CommunityGenerationAdmissionV1,
};
pub use graph_root::{
    CommunityGraphCountsV1, CommunityGraphRootInputV1, CommunityGraphRootV1,
    MAX_COMMUNITY_GRAPH_ROOT_BYTES_V1,
};
pub use guest_claim::{
    CommunityClaimArtifactV1, CommunityGuestClaimContextV1, CommunityGuestClaimKindV1,
    CommunityGuestClaimReferenceV1, CommunityGuestClaimReferencesV1, CommunityGuestClaimV1,
    COMMUNITY_CLAIM_STATE_SCHEMA_V1, COMMUNITY_GUEST_CLAIM_SCHEMA_V1,
};
pub use guest_error::{
    is_valid_community_id_v1, CommunityGuestErrorCodeV1, CommunityGuestErrorV1, FieldRefV1,
    GuestPluginErrorV1, PluginErrorCodeV1,
};
pub use host_error::{
    AtomicCommitFailureV1, CommunityPluginHostErrorV1, ComponentTrapClassV1, HostFailureClassV1,
    RevocationBasisV1, TrapReproductionV1, TrustDenialBasisV1,
};
pub use initialization::{
    CommunityInitializationProducerInputV1, CommunityInitializationProducerV1,
    CommunityInitializationRequestInputV1, CommunityInitializationRequestV1,
    CommunityInitializationSourceV1,
};
pub use input_group::{CommunityInputGroupInputV1, CommunityInputGroupV1};
pub use input_reference::{
    CommunityLocatorProducerV1, CommunityMetadataLocatorV1, CommunityNativeNodeReferenceV1,
    CommunityNativeNodeReferencesV1, CommunityTypedInputRefV1, CommunityTypedInputRefsV1,
};
pub use invocation::{
    CommunityInvocationEvidenceInputV1, CommunityInvocationEvidenceV1, CommunityOutputUsageV1,
    MeteringV1,
};
pub use key_intent::{
    CommunityKeyIntentInputV1, CommunityKeyIntentV1, CommunityKeyUseV1, CommunityMemberSlotsV1,
    CommunityRecordKindsV1, MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1,
};
pub use materialization::{
    CommunityMaterializationInputV1, CommunityMaterializationReferenceV1,
    CommunityMaterializationV1, CommunityProducerBindingV1, MAX_COMMUNITY_LOGICAL_RECORD_BYTES_V1,
};
pub use member::{CommunityMemberBindingInputV1, CommunityMemberBindingV1};
pub use member_progress::{
    CommunityCarriedEventV1, CommunityCarriedEventsIterV1, CommunityCarriedEventsV1,
    CommunityFactualNodeReferenceV1, CommunityMemberProgressInputV1, CommunityMemberProgressV1,
    CommunityProgressReferenceV1, MAX_COMMUNITY_CARRIED_EVENTS_V1,
};
pub use metadata_envelope::{CommunityMetadataEnvelopeV1, CommunityMetadataSchemaV1};
pub use metadata_scope::{
    CommunityMetadataScopeInputV1, CommunityMetadataScopeV1, CommunityScopeMemberV1,
    CommunityScopeMembersIterV1, CommunityScopeMembersV1, MAX_COMMUNITY_SCOPE_MEMBERS_V1,
};
pub use native_node::{
    CommunityContentReferenceV1, CommunityInputIndexV1, CommunityNativeNodeInputV1,
    CommunityNativeNodeKindV1, CommunityNativeNodeV1, MAX_COMMUNITY_DIRECT_INPUTS_V1,
    MAX_COMMUNITY_EXPANDED_INPUTS_V1,
};
pub use original_provenance::{CommunityOriginalProvenanceInputV1, CommunityOriginalProvenanceV1};
pub use owner_binding::{
    CommunityMetadataAnchorInputV1, CommunityMetadataAnchorV1, CommunityMetadataPolicyInputV1,
    CommunityMetadataPolicyV1, CommunityOwnerBindingInputV1, CommunityOwnerBindingV1,
};
pub use prepared::{
    CommunityPreparedInputSetV1, CommunityPreparedInvocationInputV1, CommunityPreparedInvocationV1,
    TimelinePositionV1, MAX_COMMUNITY_PREPARED_INVOCATION_BYTES_V1,
};
pub use profile::{
    CommunityDurableBackendV1, CommunityDurableProfileInputV1, CommunityDurableProfileV1,
    CommunityProfileMemberV1, CommunityProfileRetentionV1,
};
pub use progress::CommunityHostProgressV1;
pub use protected_object::{
    CommunityArtifactAdmissionInputV1, CommunityArtifactAdmissionV1, CommunityProtectedObjectV1,
};
pub use quarantine::{
    CommunityQuarantineKeyV1, CommunityQuarantineReasonEvidenceV1, CommunityQuarantineReasonV1,
    CommunityQuarantineReasonsV1, CommunityQuarantineRevisionInputV1,
    CommunityQuarantineRevisionV1,
};
pub use quarantine_control::{
    ArtifactRefV1, CommunityQuarantineControlInputV1, CommunityQuarantineControlKindV1,
    CommunityQuarantineControlV1, CommunityQuarantineDispositionV1,
    CommunityQuarantineOutcomeInputV1, CommunityQuarantineOutcomeV1,
};
pub use recording::{
    CommunityAnnotationOmissionV1, CommunityAnnotationOmissionsV1, CommunityReplayMemberBindingV1,
    CommunityReplayMemberV1, CommunityReplayRecordingInputV1, CommunityReplayRecordingV1,
};
pub use reservation::{
    CommunityReservationInputV1, CommunityReservationRequestInputV1, CommunityReservationRequestV1,
    CommunityReservationV1,
};
pub use revision::{
    CommunityStateProducerV1, CommunityStateRevisionInputV1, CommunityStateRevisionV1,
};
pub use scope_binding::{
    CommunityScopeBindingInputV1, CommunityScopeBindingV1, CommunityScopeCoverageRowV1,
    CommunityScopeCoverageRowsV1, MAX_COMMUNITY_COVERAGE_ROWS_V1,
};
pub use seal::{CommunityDigestListV1, CommunitySealedResultInputV1, CommunitySealedResultV1};
pub use selected_head::{
    CommunityMemberHeadV1, CommunityMemberHeadsV1, CommunityPassFrontierV1,
    CommunitySelectedHeadInputV1, CommunitySelectedHeadV1, MAX_COMMUNITY_MEMBERS_V1,
};
pub use selection::{
    CommunityGenerationIdsV1, CommunitySelectionInputV1, CommunitySelectionV1,
    CommunityTimelineFloorV1, CommunityTimelineFloorsV1, MAX_COMMUNITY_CLOSED_GENERATIONS_V1,
    MAX_COMMUNITY_SELECTION_TIMELINES_V1,
};
pub use source_closure::{CommunitySourceClosureInputV1, CommunitySourceClosureV1};
pub use state::{CommunityStateContentV1, MAX_COMMUNITY_STATE_BYTES_V1};
pub use step::{CommunityInvocationStepInputV1, CommunityInvocationStepV1};
pub use terminal::{
    CommunityAbortInputV1, CommunityAbortReasonV1, CommunityAbortV1, CommunityCommitInputV1,
    CommunityCommitV1, CommunityFactualRangeV1,
};

use crate::{
    encode_bytes, encode_head, CborCursor, CborReadError, Hash, ImplementationKeyV1, TimelineId,
    MAX_IMPLEMENTATION_KEY_BYTES_V1,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, CommunityLifecycleErrorV1>;

/// Maximum accepted canonical CPK1 encoding, including its framing.
pub const MAX_COMMUNITY_PASS_KEY_BYTES_V1: usize = 64;

/// A CPK1 pass coordinate, independent of Event sequence and factual Tick.
// No Debug/Serde implementation: this potentially personal identity must not
// become a log field or an alternative permissive persistence codec.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CommunityPassKeyV1 {
    timeline: TimelineId,
    generation: [u8; 16],
    ordinal: u64,
}

impl CommunityPassKeyV1 {
    /// Validate a pass coordinate without allocating or authorizing a pass.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero Timeline, generation or ordinal.
    pub fn new(timeline: TimelineId, generation: [u8; 16], ordinal: u64) -> Result<Self> {
        validate_coordinates(timeline, generation).and(if ordinal == 0 {
            Err(CommunityLifecycleErrorV1::InvalidBinding)
        } else {
            Ok(Self {
                timeline,
                generation,
                ordinal,
            })
        })
    }

    /// Return the execution Timeline.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// Return the non-reusable generation identity.
    #[must_use]
    pub const fn generation(&self) -> [u8; 16] {
        self.generation
    }

    /// Return the positive pass ordinal, never an Event or Tick coordinate.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Encode the exact preferred five-field CPK1 record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_COMMUNITY_PASS_KEY_BYTES_V1);
        record_prefix(&mut out, 5, *b"CPK1");
        encode_coordinates(&mut out, self.timeline, self.generation);
        encode_head(&mut out, 0, self.ordinal);
        out
    }

    /// Derive `BLAKE3("PiglorOS.Community.CPK1.v1\0" || CPK1)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let bytes = Zeroizing::new(self.to_canonical_cbor());
        digest(b"PiglorOS.Community.CPK1.v1\0", &bytes)
    }

    /// Decode one complete preferred CPK1 record without issuing a permit.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred framing, unknown versions, oversized
    /// records, zero coordinates and trailing bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_COMMUNITY_PASS_KEY_BYTES_V1, 5, *b"CPK1").and_then(|mut cursor| {
            read_coordinates(&mut cursor).and_then(|(timeline, generation)| {
                read_head(&mut cursor, 0)
                    .and_then(|ordinal| Self::new(timeline, generation, ordinal))
                    .and_then(|record| canonical_end(&cursor).map(|()| record))
            })
        })
    }
}

impl From<CborReadError> for CommunityLifecycleErrorV1 {
    fn from(_: CborReadError) -> Self {
        Self::InvalidEncoding
    }
}

fn validate_coordinates(timeline: TimelineId, generation: [u8; 16]) -> Result<()> {
    if timeline.inner().to_bytes() == [0; 16] || generation == [0; 16] {
        Err(CommunityLifecycleErrorV1::InvalidBinding)
    } else {
        Ok(())
    }
}

const fn validate_horizon(horizon: u64) -> Result<()> {
    if horizon == 0 || horizon > u64::MAX / 2 {
        Err(CommunityLifecycleErrorV1::BoundsExceeded)
    } else {
        Ok(())
    }
}

fn read_pass_key(cursor: &mut CborCursor<'_>) -> Result<CommunityPassKeyV1> {
    bounded_bytes(cursor, MAX_COMMUNITY_PASS_KEY_BYTES_V1)
        .and_then(CommunityPassKeyV1::from_canonical_cbor)
}

fn record_prefix(out: &mut Vec<u8>, fields: u64, magic: [u8; 4]) {
    encode_head(out, 4, fields);
    encode_bytes(out, &magic, 2);
    encode_head(out, 0, 1);
}

fn encode_coordinates(out: &mut Vec<u8>, timeline: TimelineId, generation: [u8; 16]) {
    encode_bytes(out, &timeline.inner().to_bytes(), 2);
    encode_bytes(out, &generation, 2);
}

fn record_cursor(
    bytes: &[u8],
    maximum: usize,
    fields: u64,
    magic: [u8; 4],
) -> Result<CborCursor<'_>> {
    if bytes.len() > maximum {
        return Err(CommunityLifecycleErrorV1::BoundsExceeded);
    }
    let mut expected = Vec::with_capacity(6);
    encode_head(&mut expected, 4, fields);
    encode_bytes(&mut expected, &magic, 2);
    let mut cursor = CborCursor::new(bytes);
    cursor
        .fixed(&expected)
        .map_err(CommunityLifecycleErrorV1::from)
        .and_then(|()| read_head(&mut cursor, 0))
        .and_then(|version| {
            if version == 1 {
                Ok(cursor)
            } else {
                Err(CommunityLifecycleErrorV1::UnsupportedVersion)
            }
        })
}

fn read_head(cursor: &mut CborCursor<'_>, major: u8) -> Result<u64> {
    let mut original = cursor.clone();
    cursor
        .head(major)
        .map_err(CommunityLifecycleErrorV1::from)
        .and_then(|value| {
            let mut preferred = Zeroizing::new(Vec::with_capacity(9));
            encode_head(&mut preferred, major, value);
            original
                .fixed(&preferred)
                .map_err(CommunityLifecycleErrorV1::from)
                .map(|()| value)
        })
}

fn fixed_bytes<const N: usize>(cursor: &mut CborCursor<'_>) -> Result<[u8; N]> {
    let mut head = Vec::with_capacity(9);
    encode_head(&mut head, 2, N as u64);
    cursor
        .fixed(&head)
        .and_then(|()| cursor.take(N))
        .map_err(CommunityLifecycleErrorV1::from)
        .map(|bytes| {
            let mut value = [0; N];
            value.copy_from_slice(bytes);
            value
        })
}

fn bounded_bytes<'a>(cursor: &mut CborCursor<'a>, maximum: usize) -> Result<&'a [u8]> {
    read_head(cursor, 2).and_then(|length| {
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        if length > maximum {
            Err(CommunityLifecycleErrorV1::BoundsExceeded)
        } else {
            cursor.take(length).map_err(CommunityLifecycleErrorV1::from)
        }
    })
}

fn bounded_text<'a>(cursor: &mut CborCursor<'a>, maximum: usize) -> Result<&'a str> {
    read_head(cursor, 3).and_then(|length| {
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        if length > maximum {
            return Err(CommunityLifecycleErrorV1::BoundsExceeded);
        }
        cursor
            .take(length)
            .map_err(CommunityLifecycleErrorV1::from)
            .and_then(|bytes| {
                std::str::from_utf8(bytes).map_err(|_| CommunityLifecycleErrorV1::InvalidEncoding)
            })
    })
}

fn read_hash(cursor: &mut CborCursor<'_>) -> Result<Hash> {
    fixed_bytes(cursor).map(Hash::from_bytes)
}

fn read_hashes<const N: usize>(cursor: &mut CborCursor<'_>) -> Result<[Hash; N]> {
    let mut hashes = [Hash::zero(); N];
    hashes
        .iter_mut()
        .try_for_each(|slot| read_hash(cursor).map(|hash| *slot = hash))
        .map(|()| hashes)
}

fn encode_implementation_key(out: &mut Vec<u8>, implementation: &ImplementationKeyV1) {
    let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_IMPLEMENTATION_KEY_BYTES_V1));
    implementation.write(&mut encoded);
    encode_bytes(out, &encoded, 2);
}

fn read_implementation_key(
    cursor: &mut CborCursor<'_>,
    implementation: &ImplementationKeyV1,
) -> Result<()> {
    bounded_bytes(cursor, MAX_IMPLEMENTATION_KEY_BYTES_V1).and_then(|nested| {
        let mut expected = Zeroizing::new(Vec::with_capacity(MAX_IMPLEMENTATION_KEY_BYTES_V1));
        implementation.write(&mut expected);
        if nested == expected.as_slice() {
            Ok(())
        } else {
            Err(CommunityLifecycleErrorV1::InvalidBinding)
        }
    })
}

fn read_optional_hash(cursor: &mut CborCursor<'_>) -> Result<Option<Hash>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        read_hash(cursor).map(Some)
    }
}

fn encode_optional_hash(out: &mut Vec<u8>, hash: Option<Hash>) {
    match hash {
        None => out.push(0xf6),
        Some(hash) => crate::encode_hash(out, hash),
    }
}

fn read_coordinates(cursor: &mut CborCursor<'_>) -> Result<(TimelineId, [u8; 16])> {
    fixed_bytes(cursor).and_then(|timeline| {
        fixed_bytes(cursor).map(|generation| {
            (
                TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline)),
                generation,
            )
        })
    })
}

const fn canonical_end(cursor: &CborCursor<'_>) -> Result<()> {
    if cursor.is_finished() {
        Ok(())
    } else {
        Err(CommunityLifecycleErrorV1::InvalidEncoding)
    }
}

/// Exact length of the preferred CBOR head [`encode_head`] writes for `value`.
const fn head_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
