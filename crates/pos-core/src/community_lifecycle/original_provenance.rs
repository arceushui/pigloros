//! ADR-129 §3 CPV1 original provenance.
//!
//! CPV1 binds one operation's input identity to its CSB1 scope binding, its
//! exact required direct source set, the rule bundle and the pre-Reserve
//! budget identity. `source_root_refs` uses the typed direct-input reference
//! grammar of ADR-129 §4 (the CIR1 list type) in canonical order; it never
//! names the operation's own future object, registration or receipt. Valid
//! bytes do not prove that any source exists, is current or is authorized.

use super::envelope::{encode_operation, read_operation, validate_operation};
use super::input_reference::{CommunityTypedInputRefV1, CommunityTypedInputRefsV1};
use super::native_node::MAX_COMMUNITY_EXPANDED_INPUTS_V1;
use super::{
    canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates, read_hash, read_head,
    record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityArtifactOperationV1, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

const MAX_PROVENANCE: usize = 1_048_576;

/// Untrusted CPV1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityOriginalProvenanceInputV1<'a> {
    /// Nonzero protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// ADR-128 operation kind and identity (Pass/CPK1, Initialization, Control).
    pub operation: CommunityArtifactOperationV1,
    /// Prepared CIN1/input-set digest, or the CGI1/control request digest.
    pub input_identity: Hash,
    /// ADR-128 `ScopeCover` digest of this operation's CSB1.
    pub scope_binding_digest: Hash,
    /// Exact required direct sources: at most 4096 typed refs in canonical order.
    pub source_root_refs: CommunityTypedInputRefsV1<'a>,
    /// Exact admitted rule bundle.
    pub rule_bundle_digest: Hash,
    /// Pre-Reserve budget forecast identity.
    pub budget_identity: Hash,
    /// Original positive evidence horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact thirteen-field CPV1.
pub struct CommunityOriginalProvenanceV1<'a>(CommunityOriginalProvenanceInputV1<'a>);

impl<'a> CommunityOriginalProvenanceV1<'a> {
    /// Validate local identities, source order and bounds.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero, unordered or aliased identities, a
    /// native source from another store incarnation and a pass key for another
    /// Timeline/generation, and `BoundsExceeded` for more
    /// than 4096 sources or an invalid horizon.
    pub fn new(input: CommunityOriginalProvenanceInputV1<'a>) -> Result<Self> {
        if input.store_incarnation == [0; 16]
            || [
                input.input_identity,
                input.scope_binding_digest,
                input.rule_bundle_digest,
                input.budget_identity,
            ]
            .contains(&Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_operation(input.operation, input.timeline, input.generation))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .and_then(|()| {
                input
                    .source_root_refs
                    .validate(0, MAX_COMMUNITY_EXPANDED_INPUTS_V1)
            })
            .and_then(|()| same_incarnation(input.source_root_refs, input.store_incarnation))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any source.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityOriginalProvenanceInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CPV1 into zeroizing storage pre-sized to
    /// the record bound, so no reallocation leaves an unwiped copy.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_PROVENANCE));
        record_prefix(&mut out, 13, *b"CPV1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_operation(&mut out, input.operation);
        encode_hash(&mut out, input.input_identity);
        encode_hash(&mut out, input.scope_binding_digest);
        input.source_root_refs.encode(&mut out);
        encode_hash(&mut out, input.rule_bundle_digest);
        encode_hash(&mut out, input.budget_identity);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// ADR-128 `OwnerProvenance` identity, not the generic CPV1 record domain.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.OwnerProvenance.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode one complete preferred CPV1, borrowing its source rows.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_PROVENANCE, 13, *b"CPV1").and_then(|mut cursor| {
            read_body(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

/// Native sources from another store incarnation are unsupported (§4).
fn same_incarnation(refs: CommunityTypedInputRefsV1<'_>, incarnation: [u8; 16]) -> Result<()> {
    refs.iter().try_for_each(|reference| {
        reference.and_then(|reference| match reference {
            CommunityTypedInputRefV1::Native(native) if native.store_incarnation != incarnation => {
                Err(Error::InvalidBinding)
            }
            _ => Ok(()),
        })
    })
}

fn read_body<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityOriginalProvenanceInputV1<'a>> {
    fixed_bytes(cursor).and_then(|store_incarnation| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_operation(cursor).and_then(|operation| {
                read_hash(cursor).and_then(|input_identity| {
                    read_hash(cursor).and_then(|scope_binding_digest| {
                        CommunityTypedInputRefsV1::read(cursor, MAX_COMMUNITY_EXPANDED_INPUTS_V1)
                            .and_then(|source_root_refs| {
                                read_hash(cursor).and_then(|rule_bundle_digest| {
                                    read_hash(cursor).and_then(|budget_identity| {
                                        read_head(cursor, 0).map(|evidence_not_after_micros| {
                                            CommunityOriginalProvenanceInputV1 {
                                                store_incarnation,
                                                timeline,
                                                generation,
                                                operation,
                                                input_identity,
                                                scope_binding_digest,
                                                source_root_refs,
                                                rule_bundle_digest,
                                                budget_identity,
                                                evidence_not_after_micros,
                                            }
                                        })
                                    })
                                })
                            })
                    })
                })
            })
        })
    })
}
