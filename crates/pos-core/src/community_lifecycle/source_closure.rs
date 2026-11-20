//! ADR-129 §4 CIR1 pre-Reserve source closure.
//!
//! CIR1 lists only earlier, independently admitted actual source references
//! and their independently derived scope union. It excludes the current
//! CIN1, CSB1, CPV1, producer and result identities, so `H(CIR1)` can be the
//! prepared invocation's provenance root without a cycle. Valid bytes do not
//! prove that any source exists, is current or has that scope.

use super::input_reference::CommunityTypedInputRefsV1;
use super::native_node::MAX_COMMUNITY_EXPANDED_INPUTS_V1;
use super::{
    canonical_end, digest, encode_coordinates, read_coordinates, read_hash, record_cursor,
    record_prefix, validate_coordinates, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_hash, Hash, TimelineId};
use zeroize::Zeroizing;

const MAX_CLOSURE: usize = 1_048_576;

/// Untrusted CIR1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunitySourceClosureInputV1<'a> {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// At most 4096 actual input references in canonical order.
    pub inputs: CommunityTypedInputRefsV1<'a>,
    /// Independently derived scope union of those inputs.
    pub source_scope_union_digest: Hash,
}

/// Exact six-field CIR1.
pub struct CommunitySourceClosureV1<'a>(CommunitySourceClosureInputV1<'a>);

impl<'a> CommunitySourceClosureV1<'a> {
    /// Validate coordinates, ordered inputs and the scope union identity.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero or unordered identities and
    /// `BoundsExceeded` for more than 4096 inputs.
    pub fn new(input: CommunitySourceClosureInputV1<'a>) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| {
                if input.source_scope_union_digest == Hash::zero() {
                    Err(Error::InvalidBinding)
                } else {
                    input.inputs.validate(0, MAX_COMMUNITY_EXPANDED_INPUTS_V1)
                }
            })
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any source.
    #[must_use]
    pub const fn as_input(&self) -> &CommunitySourceClosureInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CIR1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        record_prefix(&mut out, 6, *b"CIR1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        input.inputs.encode(&mut out);
        encode_hash(&mut out, input.source_scope_union_digest);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CIR1.v1\0" || CIR1)`, the provenance root.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CIR1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CIR1, borrowing its input rows.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_CLOSURE, 6, *b"CIR1").and_then(|mut cursor| {
            read_coordinates(&mut cursor)
                .and_then(|(timeline, generation)| {
                    CommunityTypedInputRefsV1::read(&mut cursor, MAX_COMMUNITY_EXPANDED_INPUTS_V1)
                        .and_then(|inputs| {
                            read_hash(&mut cursor).map(|source_scope_union_digest| {
                                CommunitySourceClosureInputV1 {
                                    timeline,
                                    generation,
                                    inputs,
                                    source_scope_union_digest,
                                }
                            })
                        })
                })
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}
