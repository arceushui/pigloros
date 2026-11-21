//! ADR-129 §6 CED1/CEB1 sealed Event-draft retention.
//!
//! Seal retains the exact Event drafts, not only their digest. The drafts are
//! one preferred CBOR array (the empty vector is its one-byte encoding),
//! partitioned into contiguous CEB1 fragments that a CED1 manifest names.
//! Valid bytes do not prove that a fragment's registration, owner or COA
//! exists or is current; the owner resolves every reference independently.
//! Reconstruction never reruns a guest.

use super::materialization::CommunityMaterializationReferenceV1;
use super::{
    bounded_bytes, bounded_text, canonical_end, digest, fixed_bytes, head_len, read_hash,
    read_head, read_pass_key, read_vec, record_cursor, record_prefix,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1, Result,
};
use crate::{
    encode_bytes, encode_hash, encode_head, pipeline_draft_vector_digest_v1, CanonicalBytes,
    CborCursor, CorrelationId, EntityId, ErasureArtifactClassV1, EventDraft, EventId, Hash, Kind,
    SchemaVersion, WallTime,
};
use ulid::Ulid;
use zeroize::Zeroizing;

/// Maximum canonical CED1 encoding.
pub const MAX_COMMUNITY_EVENT_DRAFT_MANIFEST_BYTES_V1: usize = 65_536;
/// Maximum fragments one CED1 names.
pub const MAX_COMMUNITY_EVENT_DRAFT_FRAGMENTS_V1: usize = 256;
/// Maximum raw bytes in one CEB1 fragment.
pub const MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_BYTES_V1: usize = 262_144;
/// Maximum canonical draft-vector bytes.
pub const MAX_COMMUNITY_EVENT_DRAFT_VECTOR_BYTES_V1: u64 = 67_108_864;
/// Maximum Event drafts in one vector.
pub const MAX_COMMUNITY_EVENT_DRAFTS_V1: usize = 1024;
/// Largest canonical CEB1 implied by its field bounds.
///
/// Array head, magic, version, the 64-byte CPK1 in a two-byte head, two
/// nine-byte integers and the largest fragment in a five-byte head
/// (1+5+1+66+9+9+5+262,144).
pub const MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_RECORD_BYTES_V1: usize = 262_240;
const FRAGMENT_BYTES: u32 = 262_144;
const VECTOR_BYTES: usize = 67_108_864;

/// Untrusted CEB1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityEventDraftFragmentInputV1<'a> {
    /// Original reserved CPK1.
    pub pass_key: CommunityPassKeyV1,
    /// Offset of these bytes in the canonical draft vector.
    pub byte_offset: u64,
    /// Exact length of the complete canonical draft vector.
    pub total_plaintext_bytes: u64,
    /// 1..=262,144 opaque vector bytes.
    pub fragment_bytes: &'a [u8],
}

/// Exact six-field CEB1. Its bytes stay opaque until full reconstruction.
pub struct CommunityEventDraftFragmentV1<'a>(CommunityEventDraftFragmentInputV1<'a>);

impl<'a> CommunityEventDraftFragmentV1<'a> {
    /// Validate the fragment length and its range inside the vector.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for an empty or over-262,144-byte fragment or
    /// a vector length outside 1..=64 MiB, and `InvalidBinding` when the
    /// fragment ends past the vector.
    pub fn new(input: CommunityEventDraftFragmentInputV1<'a>) -> Result<Self> {
        let length = input.fragment_bytes.len();
        if !(1..=MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_BYTES_V1).contains(&length) {
            return Err(Error::BoundsExceeded);
        }
        let within =
            if input.byte_offset.saturating_add(length as u64) > input.total_plaintext_bytes {
                Err(Error::InvalidBinding)
            } else {
                Ok(Self(input))
            };
        validate_vector_length(input.total_plaintext_bytes).and(within)
    }

    /// Borrow exact fields without resolving any registration.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityEventDraftFragmentInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CEB1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(
            MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_RECORD_BYTES_V1,
        ));
        record_prefix(&mut out, 6, *b"CEB1");
        let pass_key = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &pass_key, 2);
        encode_head(&mut out, 0, input.byte_offset);
        encode_head(&mut out, 0, input.total_plaintext_bytes);
        encode_bytes(&mut out, input.fragment_bytes, 2);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CEB1.v1\0" || CEB1)`, the CED1 fragment digest.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CEB1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CEB1, borrowing its fragment bytes.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(
            bytes,
            MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_RECORD_BYTES_V1,
            6,
            *b"CEB1",
        )
        .and_then(|mut cursor| {
            read_pass_key(&mut cursor).and_then(|pass_key| {
                read_head(&mut cursor, 0).and_then(|byte_offset| {
                    read_head(&mut cursor, 0).and_then(|total_plaintext_bytes| {
                        bounded_bytes(&mut cursor, MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_BYTES_V1)
                            .and_then(|fragment_bytes| {
                                canonical_end(&cursor).and_then(|()| {
                                    Self::new(CommunityEventDraftFragmentInputV1 {
                                        pass_key,
                                        byte_offset,
                                        total_plaintext_bytes,
                                        fragment_bytes,
                                    })
                                })
                            })
                    })
                })
            })
        })
    }
}

/// Exact `[byte_offset_u64, fragment_length_u32, CEB1_digest32,
/// materialization_ref]` naming one CEB1.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityEventDraftFragmentReferenceV1 {
    /// Contiguous offset in the canonical draft vector.
    pub byte_offset: u64,
    /// 1..=262,144 fragment bytes.
    pub fragment_length: u32,
    /// `H(CEB1)` of the referenced fragment.
    pub fragment_digest: Hash,
    /// CMI1-grammar materialization of the CEB1 bytes, class `TimelineReplay`.
    pub materialization: CommunityMaterializationReferenceV1,
}

/// Untrusted CED1 fields.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityEventDraftManifestInputV1 {
    /// Original reserved CPK1.
    pub pass_key: CommunityPassKeyV1,
    /// 1..=256 references partitioning the vector in offset order.
    pub fragments: Vec<CommunityEventDraftFragmentReferenceV1>,
    /// Exact canonical draft-vector length, 1..=64 MiB.
    pub total_plaintext_bytes: u64,
    /// Number of drafts, at most 1,024.
    pub draft_count: u64,
    /// Existing `pipeline_draft_vector_digest_v1` of the drafts.
    pub draft_vector_digest: Hash,
}

/// Exact seven-field CED1. It names sealed drafts; it cannot publish them.
pub struct CommunityEventDraftManifestV1(CommunityEventDraftManifestInputV1);

impl CommunityEventDraftManifestV1 {
    /// Validate the bounds and that the references partition the vector
    /// exactly once, starting at offset zero.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for more than 256 references, a reference
    /// length outside 1..=262,144, a vector length outside 1..=64 MiB or more
    /// than 1,024 drafts, and `InvalidBinding` for a zero digest, a
    /// noncontiguous or incomplete partition, or an invalid materialization.
    pub fn new(input: CommunityEventDraftManifestInputV1) -> Result<Self> {
        if input.fragments.len() > MAX_COMMUNITY_EVENT_DRAFT_FRAGMENTS_V1
            || input.draft_count > MAX_COMMUNITY_EVENT_DRAFTS_V1 as u64
        {
            return Err(Error::BoundsExceeded);
        }
        if input.draft_vector_digest == Hash::zero() {
            return Err(Error::InvalidBinding);
        }
        validate_vector_length(input.total_plaintext_bytes)
            .and_then(|()| {
                input
                    .fragments
                    .iter()
                    .try_fold(0, |offset, fragment| validate_reference(offset, *fragment))
            })
            .and_then(|end| {
                if end == input.total_plaintext_bytes {
                    Ok(Self(input))
                } else {
                    Err(Error::InvalidBinding)
                }
            })
    }

    /// Borrow exact fields without resolving any fragment.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityEventDraftManifestInputV1 {
        &self.0
    }

    /// Encode the complete preferred CED1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(
            MAX_COMMUNITY_EVENT_DRAFT_MANIFEST_BYTES_V1,
        ));
        record_prefix(&mut out, 7, *b"CED1");
        let pass_key = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &pass_key, 2);
        encode_head(&mut out, 4, input.fragments.len() as u64);
        for fragment in &input.fragments {
            out.push(0x84);
            encode_head(&mut out, 0, fragment.byte_offset);
            encode_head(&mut out, 0, u64::from(fragment.fragment_length));
            encode_hash(&mut out, fragment.fragment_digest);
            fragment.materialization.encode(&mut out);
        }
        encode_head(&mut out, 0, input.total_plaintext_bytes);
        encode_head(&mut out, 0, input.draft_count);
        encode_hash(&mut out, input.draft_vector_digest);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CED1.v1\0" || CED1)`, the CPS1 manifest digest.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CED1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CED1.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(
            bytes,
            MAX_COMMUNITY_EVENT_DRAFT_MANIFEST_BYTES_V1,
            7,
            *b"CED1",
        )
        .and_then(|mut cursor| {
            read_manifest(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }

    /// Reassemble the referenced CEB1 fragments, in reference order, and
    /// return the exact validated drafts.
    ///
    /// # Errors
    /// Returns `InvalidBinding` when the fragments are not exactly the
    /// referenced CEB1 records of this pass and vector, or the decoded drafts
    /// do not match the recorded count and vector digest; otherwise the draft
    /// vector's own decoding errors.
    pub fn reconstruct(
        &self,
        fragments: &[CommunityEventDraftFragmentV1<'_>],
    ) -> Result<Vec<EventDraft>> {
        let input = self.as_input();
        if fragments.len() != input.fragments.len() {
            return Err(Error::InvalidBinding);
        }
        let mut vector = Zeroizing::new(Vec::with_capacity(
            usize::try_from(input.total_plaintext_bytes).unwrap_or(0),
        ));
        input
            .fragments
            .iter()
            .zip(fragments)
            .try_for_each(|(reference, fragment)| {
                let actual = fragment.as_input();
                if (
                    actual.pass_key,
                    actual.byte_offset,
                    actual.total_plaintext_bytes,
                    actual.fragment_bytes.len() as u64,
                ) != (
                    input.pass_key,
                    reference.byte_offset,
                    input.total_plaintext_bytes,
                    u64::from(reference.fragment_length),
                ) || fragment.digest() != reference.fragment_digest
                {
                    Err(Error::InvalidBinding)
                } else {
                    vector.extend_from_slice(actual.fragment_bytes);
                    Ok(())
                }
            })
            .and_then(|()| read_draft_vector(&vector))
            .and_then(|drafts| {
                if drafts.len() as u64 == input.draft_count
                    && pipeline_draft_vector_digest_v1(&drafts) == input.draft_vector_digest
                {
                    Ok(drafts)
                } else {
                    Err(Error::InvalidBinding)
                }
            })
    }
}

/// Encode the canonical CED1/CEB1 draft vector.
///
/// The vector is a preferred array of exact `[entity16, event_type_text,
/// payload_bytes, causation_id_or_null, correlation_id_or_null,
/// schema_version_u32, wall_time_micros_or_null]` drafts. The empty vector is the one byte `0x80`.
///
/// # Errors
/// Returns `BoundsExceeded` for more than 1,024 drafts or over 64 MiB of
/// canonical bytes, and `InvalidBinding` for a nil entity, causation or
/// correlation identifier or an empty Event type.
pub fn community_event_draft_vector_bytes_v1(drafts: &[EventDraft]) -> Result<Zeroizing<Vec<u8>>> {
    if drafts.len() > MAX_COMMUNITY_EVENT_DRAFTS_V1 {
        return Err(Error::BoundsExceeded);
    }
    drafts.iter().try_for_each(validate_draft).and_then(|()| {
        let length = drafts
            .iter()
            .fold(head_len(drafts.len() as u64), |sum, draft| {
                sum.saturating_add(draft_len(draft))
            });
        if length > VECTOR_BYTES {
            return Err(Error::BoundsExceeded);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(length));
        encode_head(&mut out, 4, drafts.len() as u64);
        for draft in drafts {
            encode_draft(&mut out, draft);
        }
        Ok(out)
    })
}

fn validate_vector_length(length: u64) -> Result<()> {
    if (1..=MAX_COMMUNITY_EVENT_DRAFT_VECTOR_BYTES_V1).contains(&length) {
        Ok(())
    } else {
        Err(Error::BoundsExceeded)
    }
}

fn validate_reference(
    offset: u64,
    fragment: CommunityEventDraftFragmentReferenceV1,
) -> Result<u64> {
    if !(1..=FRAGMENT_BYTES).contains(&fragment.fragment_length) {
        Err(Error::BoundsExceeded)
    } else if fragment.byte_offset != offset
        || fragment.fragment_digest == Hash::zero()
        || fragment.materialization.artifact_class != ErasureArtifactClassV1::TimelineReplay
    {
        Err(Error::InvalidBinding)
    } else {
        fragment
            .materialization
            .validate()
            .map(|()| offset + u64::from(fragment.fragment_length))
    }
}

fn read_manifest(cursor: &mut CborCursor<'_>) -> Result<CommunityEventDraftManifestInputV1> {
    read_pass_key(cursor).and_then(|pass_key| {
        read_vec(
            cursor,
            MAX_COMMUNITY_EVENT_DRAFT_FRAGMENTS_V1,
            read_reference,
        )
        .and_then(|fragments| {
            read_head(cursor, 0).and_then(|total_plaintext_bytes| {
                read_head(cursor, 0).and_then(|draft_count| {
                    read_hash(cursor).map(|draft_vector_digest| {
                        CommunityEventDraftManifestInputV1 {
                            pass_key,
                            fragments,
                            total_plaintext_bytes,
                            draft_count,
                            draft_vector_digest,
                        }
                    })
                })
            })
        })
    })
}

fn read_reference(cursor: &mut CborCursor<'_>) -> Result<CommunityEventDraftFragmentReferenceV1> {
    cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
        read_head(cursor, 0).and_then(|byte_offset| {
            read_head(cursor, 0)
                .and_then(|length| u32::try_from(length).map_err(|_| Error::BoundsExceeded))
                .and_then(|fragment_length| {
                    read_hash(cursor).and_then(|fragment_digest| {
                        CommunityMaterializationReferenceV1::read(cursor).map(|materialization| {
                            CommunityEventDraftFragmentReferenceV1 {
                                byte_offset,
                                fragment_length,
                                fragment_digest,
                                materialization,
                            }
                        })
                    })
                })
        })
    })
}

fn validate_draft(draft: &EventDraft) -> Result<()> {
    if crate::pipeline::invalid_draft(draft)
        || draft
            .causation_id
            .is_some_and(|id| id.inner() == Ulid::nil())
        || draft
            .correlation_id
            .is_some_and(|id| id.inner() == Ulid::nil())
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

/// Exact encoded length of [`encode_draft`]'s output for `draft`.
fn draft_len(draft: &EventDraft) -> usize {
    let text = draft.event_type.as_str().len();
    let payload = draft.payload.len();
    let optional_id = |present: bool| if present { 17 } else { 1 };
    [
        1 + 17,
        head_len(text as u64),
        text,
        head_len(payload as u64),
        payload,
        optional_id(draft.causation_id.is_some()),
        optional_id(draft.correlation_id.is_some()),
        head_len(u64::from(draft.schema_version.as_u32())),
        draft.wall_time.map_or(1, |time| head_len(time.as_micros())),
    ]
    .into_iter()
    .fold(0, usize::saturating_add)
}

fn encode_draft(out: &mut Vec<u8>, draft: &EventDraft) {
    out.push(0x87);
    encode_bytes(out, &draft.entity.inner().to_bytes(), 2);
    encode_bytes(out, draft.event_type.as_str().as_bytes(), 3);
    encode_bytes(out, draft.payload.as_slice(), 2);
    for id in [
        draft.causation_id.as_ref().map(EventId::inner),
        draft.correlation_id.as_ref().map(CorrelationId::inner),
    ] {
        match id {
            Some(id) => encode_bytes(out, &id.to_bytes(), 2),
            None => out.push(0xf6),
        }
    }
    encode_head(out, 0, u64::from(draft.schema_version.as_u32()));
    match draft.wall_time {
        Some(time) => encode_head(out, 0, time.as_micros()),
        None => out.push(0xf6),
    }
}

fn read_draft_vector(bytes: &[u8]) -> Result<Vec<EventDraft>> {
    let mut cursor = CborCursor::new(bytes);
    read_vec(&mut cursor, MAX_COMMUNITY_EVENT_DRAFTS_V1, read_draft)
        .and_then(|drafts| canonical_end(&cursor).map(|()| drafts))
}

fn read_draft(cursor: &mut CborCursor<'_>) -> Result<EventDraft> {
    cursor
        .fixed(&[0x87])
        .map_err(Error::from)
        .and_then(|()| {
            fixed_bytes(cursor).and_then(|entity| {
                bounded_text(cursor, VECTOR_BYTES).and_then(|event_type| {
                    bounded_bytes(cursor, VECTOR_BYTES).and_then(|payload| {
                        read_optional_id(cursor).and_then(|causation| {
                            read_optional_id(cursor).and_then(|correlation| {
                                read_schema_version(cursor).and_then(|schema_version| {
                                    read_wall_time(cursor).map(|wall_time| EventDraft {
                                        entity: EntityId::from_ulid(Ulid::from_bytes(entity)),
                                        event_type: Kind::new(event_type),
                                        payload: CanonicalBytes::from_vec(payload.to_vec()),
                                        causation_id: causation.map(EventId::from_ulid),
                                        correlation_id: correlation.map(CorrelationId::from_ulid),
                                        schema_version,
                                        wall_time,
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
        .and_then(|draft| validate_draft(&draft).map(|()| draft))
}

fn read_optional_id(cursor: &mut CborCursor<'_>) -> Result<Option<Ulid>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        fixed_bytes(cursor).map(|id| Some(Ulid::from_bytes(id)))
    }
}

fn read_schema_version(cursor: &mut CborCursor<'_>) -> Result<SchemaVersion> {
    read_head(cursor, 0).and_then(|version| {
        if version == u64::from(SchemaVersion::V1.as_u32()) {
            Ok(SchemaVersion::V1)
        } else {
            Err(Error::InvalidEncoding)
        }
    })
}

fn read_wall_time(cursor: &mut CborCursor<'_>) -> Result<Option<WallTime>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        read_head(cursor, 0).map(|micros| Some(WallTime::from_micros(micros)))
    }
}
