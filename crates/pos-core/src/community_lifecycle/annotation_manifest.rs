//! CAT1 retained presentation annotation aggregate.
//!
//! CAT1 is a `PresentationOnly` guest-claim artifact: not a host CTR1, an
//! authorization decision, an Event or a simulation input. Valid bytes prove
//! only the wire shape and local bounds. Each item's GCA1 is compared with the
//! actual invocation through [`CommunityAnnotationManifestV1::validate_claims`],
//! and the owner resolves every annotation input digest independently.

use super::seal::{encode_list, read_bounded_list};
use super::{
    bounded_bytes, canonical_end, digest, read_hashes, read_head, read_pass_key, read_vec,
    record_cursor, record_prefix, validate_horizon, CommunityDigestListV1,
    CommunityGuestClaimContextV1, CommunityGuestClaimV1, CommunityLifecycleErrorV1 as Error,
    CommunityPassKeyV1, Result, COMMUNITY_GUEST_CLAIM_SCHEMA_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

/// Maximum canonical CAT1 encoding.
pub const MAX_COMMUNITY_ANNOTATION_MANIFEST_BYTES_V1: usize = 2_097_152;
/// Maximum items one CAT1 retains.
pub const MAX_COMMUNITY_ANNOTATION_ITEMS_V1: usize = 1024;
/// Maximum summed GCA1 bytes over every item.
pub const MAX_COMMUNITY_ANNOTATION_CLAIM_BYTES_V1: usize = 1_048_576;
/// Maximum resolved annotation input digests in one item.
pub const MAX_COMMUNITY_ANNOTATION_INPUT_REFS_V1: usize = 4096;
/// Largest guest index, below the 64-member roster cap.
pub const MAX_COMMUNITY_ANNOTATION_GUEST_INDEX_V1: u64 = 63;

/// One `[guest_index, GCA1_bytes, resolved_annotation_input_refs]` item.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityAnnotationItemV1<'a> {
    /// Guest annotation index, 0..=63, nondecreasing across items.
    pub guest_index: u64,
    /// Exact preferred GCA1 claim bytes.
    pub claim_bytes: &'a [u8],
    /// At most 4,096 strictly ascending nonzero resolved input digests.
    pub resolved_input_digests: CommunityDigestListV1<'a>,
}

/// Untrusted CAT1 fields.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityAnnotationManifestInputV1<'a> {
    /// Original reserved CPK1.
    pub pass_key: CommunityPassKeyV1,
    /// Exact CMB1 of the annotating member.
    pub member_binding_digest: Hash,
    /// Exact CPI1 invocation step.
    pub invocation_step_digest: Hash,
    /// 1..=1,024 retained items in ascending guest index.
    pub items: Vec<CommunityAnnotationItemV1<'a>>,
    /// Fixed positive horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact seven-field CAT1. It grants no authorization or retention right.
pub struct CommunityAnnotationManifestV1<'a>(CommunityAnnotationManifestInputV1<'a>);

impl<'a> CommunityAnnotationManifestV1<'a> {
    /// Validate links, item order and every count and byte bound.
    ///
    /// An empty CAT1 is refused. This is inferred from ADR-129 §6: "Retain
    /// no aggregate when that complete input set/budget would fail", and CPS1
    /// names an annotation manifest only when validated items were retained.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for no or more than 1,024 items, a guest
    /// index over 63, more than 4,096 digests in an item, over 1 MiB of
    /// summed GCA1 bytes, an invalid horizon or an encoding over 2 MiB, and
    /// `InvalidBinding` for a zero link or digest, a decreasing guest index or
    /// digests that are not strictly ascending.
    pub fn new(input: CommunityAnnotationManifestInputV1<'a>) -> Result<Self> {
        let claim_bytes = input.items.iter().fold(0, |sum: usize, item| {
            sum.saturating_add(item.claim_bytes.len())
        });
        if !(1..=MAX_COMMUNITY_ANNOTATION_ITEMS_V1).contains(&input.items.len())
            || claim_bytes > MAX_COMMUNITY_ANNOTATION_CLAIM_BYTES_V1
        {
            return Err(Error::BoundsExceeded);
        }
        if [input.member_binding_digest, input.invocation_step_digest].contains(&Hash::zero()) {
            return Err(Error::InvalidBinding);
        }
        input
            .items
            .iter()
            .try_fold(0, |floor, item| validate_item(floor, *item))
            .and_then(|_| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
            // This re-encodes up to 2 MiB only to check the size. On the
            // decode path it is redundant: `record_cursor` already enforced
            // the same cap on the input bytes.
            .and_then(|manifest| {
                if manifest.to_canonical_cbor().len() > MAX_COMMUNITY_ANNOTATION_MANIFEST_BYTES_V1 {
                    Err(Error::BoundsExceeded)
                } else {
                    Ok(manifest)
                }
            })
    }

    /// Borrow exact fields without validating any claim.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityAnnotationManifestInputV1<'a> {
        &self.0
    }

    /// Compare every retained GCA1 with the actual invocation's delivered
    /// inputs and validated output.
    ///
    /// # Errors
    /// Returns the first item's GCA1 validation error.
    pub fn validate_claims(&self, context: &CommunityGuestClaimContextV1<'_>) -> Result<()> {
        self.as_input().items.iter().try_for_each(|item| {
            CommunityGuestClaimV1::validate_annotation(
                COMMUNITY_GUEST_CLAIM_SCHEMA_V1,
                item.claim_bytes,
                context,
            )
            .map(|_| ())
        })
    }

    /// Encode the complete preferred CAT1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(
            MAX_COMMUNITY_ANNOTATION_MANIFEST_BYTES_V1,
        ));
        record_prefix(&mut out, 7, *b"CAT1");
        let pass_key = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &pass_key, 2);
        encode_hash(&mut out, input.member_binding_digest);
        encode_hash(&mut out, input.invocation_step_digest);
        encode_head(&mut out, 4, input.items.len() as u64);
        for item in &input.items {
            out.push(0x83);
            encode_head(&mut out, 0, item.guest_index);
            encode_bytes(&mut out, item.claim_bytes, 2);
            encode_list(&mut out, item.resolved_input_digests);
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CAT1.v1\0" || CAT1)`, the CPS1 annotation
    /// manifest digest.
    #[must_use]
    pub fn digest(&self) -> Hash {
        self.identity().0
    }

    /// The CAT1 digest and its encoding from one encoding.
    pub(super) fn identity(&self) -> (Hash, Zeroizing<Vec<u8>>) {
        let encoded = self.to_canonical_cbor();
        (digest(b"PiglorOS.Community.CAT1.v1\0", &encoded), encoded)
    }

    /// Decode one complete preferred CAT1, borrowing claims and digests.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(
            bytes,
            MAX_COMMUNITY_ANNOTATION_MANIFEST_BYTES_V1,
            7,
            *b"CAT1",
        )
        .and_then(|mut cursor| {
            read_manifest(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

/// Check one item against the running guest-index floor.
///
/// Guest indices may repeat in nondecreasing order: one
/// guest may contribute several items, which keeps the 1,024-item limit
/// reachable with indices 0..=63. Bound violations take precedence over
/// ordering violations.
fn validate_item(floor: u64, item: CommunityAnnotationItemV1<'_>) -> Result<u64> {
    let digests: Vec<Hash> = item.resolved_input_digests.iter().collect();
    if item.guest_index > MAX_COMMUNITY_ANNOTATION_GUEST_INDEX_V1
        || digests.len() > MAX_COMMUNITY_ANNOTATION_INPUT_REFS_V1
    {
        Err(Error::BoundsExceeded)
    } else if item.guest_index < floor
        || digests.contains(&Hash::zero())
        || digests.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(item.guest_index)
    }
}

fn read_manifest<'a>(
    cursor: &mut CborCursor<'a>,
) -> Result<CommunityAnnotationManifestInputV1<'a>> {
    read_pass_key(cursor).and_then(|pass_key| {
        read_hashes(cursor).and_then(|[member_binding_digest, invocation_step_digest]| {
            read_vec(cursor, MAX_COMMUNITY_ANNOTATION_ITEMS_V1, read_item).and_then(|items| {
                read_head(cursor, 0).map(|evidence_not_after_micros| {
                    CommunityAnnotationManifestInputV1 {
                        pass_key,
                        member_binding_digest,
                        invocation_step_digest,
                        items,
                        evidence_not_after_micros,
                    }
                })
            })
        })
    })
}

fn read_item<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityAnnotationItemV1<'a>> {
    cursor.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
        read_head(cursor, 0).and_then(|guest_index| {
            bounded_bytes(cursor, MAX_COMMUNITY_ANNOTATION_CLAIM_BYTES_V1).and_then(|claim_bytes| {
                read_bounded_list(cursor, MAX_COMMUNITY_ANNOTATION_INPUT_REFS_V1).map(
                    |resolved_input_digests| CommunityAnnotationItemV1 {
                        guest_index,
                        claim_bytes,
                        resolved_input_digests,
                    },
                )
            })
        })
    })
}
