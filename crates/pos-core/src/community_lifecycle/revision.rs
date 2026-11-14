//! CSR1 producer identity and required predecessor; no live selection authority.

use super::{
    canonical_end, encode_optional_hash, fixed_bytes, read_hash, read_hashes, read_head,
    read_optional_hash, read_pass_key, record_cursor, record_prefix, validate_horizon,
    CommunityLifecycleErrorV1, CommunityPassKeyV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

const MAX_RECORD_BYTES: usize = 512;

/// The exact activity that produced a State revision.
///
/// Initialization is a control operation, including generation transition or
/// ordinary Fork. It never borrows or fabricates a pass ordinal.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityStateProducerV1 {
    /// Admitted CGI1 request and its original nonzero control operation ID.
    Initialization {
        /// Exact admitted CGI1 request identity.
        generation_request_digest: Hash,
        /// Original initialization control identity.
        operation_id: [u8; 16],
    },
    /// A real reserved pass, whose selected predecessor remains required.
    Pass(CommunityPassKeyV1),
}

/// Untrusted CSR1 fields; construction checks shape, not producing evidence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityStateRevisionInputV1 {
    /// Original initialization or pass coordinate.
    pub producer_origin: CommunityStateProducerV1,
    /// Exact immutable CMB1 member identity.
    pub member_binding_digest: Hash,
    /// Required prior CSR1 for a pass, null only for initialization.
    pub predecessor_revision_digest: Option<Hash>,
    /// Exact CSC1 content identity, even when its bytes equal the predecessor.
    pub state_content_digest: Hash,
    /// CIS1 for initialization or input-only CPI1 for a pass, never CIV1.
    pub producer_digest: Hash,
    /// Exact protected owner binding.
    pub protected_owner_binding_digest: Hash,
    /// Fixed admitted evidence horizon, not a live authorization deadline.
    pub evidence_not_after_micros: u64,
}

/// Immutable structural CSR1; the qualified owner authenticates every link.
///
/// A valid encoding alone does not prove its predecessor was selected, its
/// producer ran, or the underlying value is retained/current/authorized.
/// No Debug/Serialize implementation exposes these potentially personal links.
pub struct CommunityStateRevisionV1(CommunityStateRevisionInputV1);

impl CommunityStateRevisionV1 {
    /// Check nonzero identities, origin/predecessor shape and horizon bounds.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero identity or wrong predecessor form;
    /// `BoundsExceeded` for a zero or non-i64 positive evidence horizon.
    pub fn new(input: CommunityStateRevisionInputV1) -> Result<Self> {
        validate_origin(input.producer_origin).and_then(|()| {
            if [
                input.member_binding_digest,
                input.state_content_digest,
                input.producer_digest,
                input.protected_owner_binding_digest,
            ]
            .contains(&Hash::zero())
                || input.predecessor_revision_digest == Some(Hash::zero())
                || matches!(
                    (input.producer_origin, input.predecessor_revision_digest),
                    (CommunityStateProducerV1::Initialization { .. }, Some(_))
                        | (CommunityStateProducerV1::Pass(_), None)
                )
            {
                return Err(CommunityLifecycleErrorV1::InvalidBinding);
            }
            validate_horizon(input.evidence_not_after_micros).map(|()| Self(input))
        })
    }

    /// Borrow the exact structural fields without authenticating their source.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityStateRevisionInputV1 {
        &self.0
    }

    /// Encode the exact nine-field CSR1 in a pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_RECORD_BYTES));
        record_prefix(&mut out, 9, *b"CSR1");
        encode_origin(&mut out, input.producer_origin);
        encode_hash(&mut out, input.member_binding_digest);
        encode_optional_hash(&mut out, input.predecessor_revision_digest);
        encode_hash(&mut out, input.state_content_digest);
        encode_hash(&mut out, input.producer_digest);
        encode_hash(&mut out, input.protected_owner_binding_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Decode one whole preferred CSR1 and enforce its local link invariants.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing data, unknown versions, bounds
    /// and invalid identities or origin/predecessor combinations.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_RECORD_BYTES, 9, *b"CSR1").and_then(|mut cursor| {
            read_input(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

fn validate_origin(origin: CommunityStateProducerV1) -> Result<()> {
    match origin {
        CommunityStateProducerV1::Initialization {
            generation_request_digest,
            operation_id,
        } if generation_request_digest == Hash::zero() || operation_id == [0; 16] => {
            Err(CommunityLifecycleErrorV1::InvalidBinding)
        }
        CommunityStateProducerV1::Initialization { .. } | CommunityStateProducerV1::Pass(_) => {
            Ok(())
        }
    }
}

fn encode_origin(out: &mut Vec<u8>, origin: CommunityStateProducerV1) {
    match origin {
        CommunityStateProducerV1::Initialization {
            generation_request_digest,
            operation_id,
        } => {
            out.extend_from_slice(&[0x83, 0]);
            encode_hash(out, generation_request_digest);
            encode_bytes(out, &operation_id, 2);
        }
        CommunityStateProducerV1::Pass(key) => {
            out.extend_from_slice(&[0x82, 1]);
            let key_bytes = Zeroizing::new(key.to_canonical_cbor());
            encode_bytes(out, &key_bytes, 2);
        }
    }
}

fn read_origin(cursor: &mut CborCursor<'_>) -> Result<CommunityStateProducerV1> {
    read_head(cursor, 4).and_then(|fields| {
        read_head(cursor, 0).and_then(|tag| match (fields, tag) {
            (3, 0) => read_hash(cursor).and_then(|generation_request_digest| {
                fixed_bytes(cursor).map(|operation_id| CommunityStateProducerV1::Initialization {
                    generation_request_digest,
                    operation_id,
                })
            }),
            (2, 1) => read_pass_key(cursor).map(CommunityStateProducerV1::Pass),
            _ => Err(CommunityLifecycleErrorV1::InvalidEncoding),
        })
    })
}

fn read_input(cursor: &mut CborCursor<'_>) -> Result<CommunityStateRevisionInputV1> {
    read_origin(cursor).and_then(|producer_origin| {
        read_hash(cursor).and_then(|member_binding_digest| {
            read_optional_hash(cursor).and_then(|predecessor_revision_digest| {
                read_hashes::<3>(cursor).and_then(
                    |[state_content_digest, producer_digest, protected_owner_binding_digest]| {
                        read_head(cursor, 0).map(|evidence_not_after_micros| {
                            CommunityStateRevisionInputV1 {
                                producer_origin,
                                member_binding_digest,
                                predecessor_revision_digest,
                                state_content_digest,
                                producer_digest,
                                protected_owner_binding_digest,
                                evidence_not_after_micros,
                            }
                        })
                    },
                )
            })
        })
    })
}
