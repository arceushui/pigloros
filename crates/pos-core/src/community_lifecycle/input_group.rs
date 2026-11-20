//! ADR-129 §4 CIB1 input group: one consecutive chunk of a consumer's
//! globally sorted unique input list. Grouping is representation only; every
//! leaf remains a required, scope-validated and charged edge.

use super::input_reference::CommunityTypedInputRefsV1;
use super::native_node::{CommunityContentReferenceV1, MAX_COMMUNITY_DIRECT_INPUTS_V1};
use super::{
    canonical_end, digest, encode_coordinates, read_coordinates, record_cursor, record_prefix,
    validate_coordinates, Result,
};
use crate::{Hash, TimelineId};
use zeroize::Zeroizing;

const MAX_GROUP: usize = 65_536;

/// Untrusted CIB1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityInputGroupInputV1<'a> {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// Logical content of the consuming node.
    pub consumer_content: CommunityContentReferenceV1,
    /// 1..=256 leaf references in canonical order.
    pub leaves: CommunityTypedInputRefsV1<'a>,
}

/// Exact six-field CIB1. It cannot replace ancestry with a summary.
pub struct CommunityInputGroupV1<'a>(CommunityInputGroupInputV1<'a>);

impl<'a> CommunityInputGroupV1<'a> {
    /// Validate coordinates, the consumer content and ordered leaves.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero or unordered identities and
    /// `BoundsExceeded` for an empty or over-256 leaf list.
    pub fn new(input: CommunityInputGroupInputV1<'a>) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| input.consumer_content.validate())
            .and_then(|()| input.leaves.validate(1, MAX_COMMUNITY_DIRECT_INPUTS_V1))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any leaf.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityInputGroupInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CIB1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_GROUP));
        record_prefix(&mut out, 6, *b"CIB1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        input.consumer_content.encode(&mut out);
        input.leaves.encode(&mut out);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CIB1.v1\0" || CIB1)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CIB1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CIB1, borrowing its leaf rows.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_GROUP, 6, *b"CIB1").and_then(|mut cursor| {
            read_coordinates(&mut cursor)
                .and_then(|(timeline, generation)| {
                    CommunityContentReferenceV1::read(&mut cursor).and_then(|consumer_content| {
                        CommunityTypedInputRefsV1::read(&mut cursor, MAX_COMMUNITY_DIRECT_INPUTS_V1)
                            .map(|leaves| CommunityInputGroupInputV1 {
                                timeline,
                                generation,
                                consumer_content,
                                leaves,
                            })
                    })
                })
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}
