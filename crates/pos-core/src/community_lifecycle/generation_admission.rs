//! Original CGA1 result data; decoding never admits or selects a generation.

use super::{
    canonical_end, encode_coordinates, read_coordinates, read_hash, read_hashes, read_head,
    record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

const MAX_RECORD_BYTES: usize = 1024;

/// Exact original generation-result claims, without an admission capability.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityGenerationAdmissionInputV1 {
    /// Exact original CGI1 request identity, never a future receipt identity.
    pub generation_request_digest: Hash,
    /// Original execution Timeline.
    pub timeline: TimelineId,
    /// Original admitted-generation claim; its actual selection needs the owner.
    pub generation: [u8; 16],
    /// Exact complete initial CSH1 identity.
    pub initial_selected_head_digest: Hash,
    /// Logical CGR1 reference, not permission to traverse or trust its graph.
    pub graph_root_ref: Hash,
    /// Fixed original evidence horizon; discovery must not renew it.
    pub evidence_not_after_micros: u64,
}

/// Eight-field CGA1 result data, with no pass ordinal or guest permit.
///
/// The actual owner must authenticate the original request, selected head,
/// complete graph and atomic outcome before using these potentially personal
/// references. Normative H(CGA1) is computed only inside that qualified owner's
/// audited private-hashing/copy boundary, not by this portable codec.
///
/// ```compile_fail,E0599
/// use pos_core::community_lifecycle::CommunityGenerationAdmissionV1;
/// fn unqualified_identity(record: &CommunityGenerationAdmissionV1) {
///     let _ = record.digest();
/// }
/// ```
pub struct CommunityGenerationAdmissionV1(CommunityGenerationAdmissionInputV1);

impl CommunityGenerationAdmissionV1 {
    /// Check local identities and horizon without establishing admission.
    ///
    /// # Errors
    /// Rejects zero request/Timeline/generation/head/root identities with
    /// `InvalidBinding`, or a zero/non-i64 evidence horizon with `BoundsExceeded`.
    pub fn new(input: CommunityGenerationAdmissionInputV1) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation).and_then(|()| {
            if [
                input.generation_request_digest,
                input.initial_selected_head_digest,
                input.graph_root_ref,
            ]
            .contains(&Hash::zero())
            {
                return Err(Error::InvalidBinding);
            }
            validate_horizon(input.evidence_not_after_micros).map(|()| Self(input))
        })
    }

    /// Borrow exact untrusted result fields without selecting a live generation.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityGenerationAdmissionInputV1 {
        &self.0
    }

    /// Encode the complete preferred CGA1 in one bounded zeroizing buffer.
    ///
    /// Its fixed-width identities and bounded horizon need at most 152 bytes,
    /// within the record's 1024-byte initial allocation and wire limit.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_RECORD_BYTES));
        record_prefix(&mut out, 8, *b"CGA1");
        encode_hash(&mut out, input.generation_request_digest);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_hash(&mut out, input.initial_selected_head_digest);
        encode_hash(&mut out, input.graph_root_ref);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Decode one whole preferred result without admitting its claimed sources.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing or oversized encodings, unknown
    /// versions and invalid local identities or evidence horizons.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_RECORD_BYTES, 8, *b"CGA1").and_then(|mut cursor| {
            read_input(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

fn read_input(cursor: &mut CborCursor<'_>) -> Result<CommunityGenerationAdmissionInputV1> {
    read_hash(cursor).and_then(|generation_request_digest| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_hashes(cursor).and_then(|[initial_selected_head_digest, graph_root_ref]| {
                read_head(cursor, 0).map(|evidence_not_after_micros| {
                    CommunityGenerationAdmissionInputV1 {
                        generation_request_digest,
                        timeline,
                        generation,
                        initial_selected_head_digest,
                        graph_root_ref,
                        evidence_not_after_micros,
                    }
                })
            })
        })
    })
}
