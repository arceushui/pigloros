//! ADR-129 §3 CAU1 current authority evidence (revision 6, R6.6).
//!
//! CAU1 commits one operation's current admission evidence: the exact
//! objects it admitted, the inventory generation and current view it read,
//! every authority decision it evaluated, its recipient and its trusted-clock
//! bound. Valid bytes do not prove that any decision was evaluated, that a
//! leaf grant resolves, or that the premise digest is H(CAV1) of a real view:
//! the concrete owner derives CAU1 from its own evaluation and checks those
//! bindings. A decoded CAU1 never selects a current source.

use super::envelope::{encode_operation, operation_len, read_operation, validate_operation};
use super::{
    canonical_end, digest, encode_coordinates, fixed_bytes, head_len, read_coordinates, read_hash,
    read_head, read_vec, record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityArtifactOperationV1, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

/// Maximum CAU1 object-binding rows.
pub const MAX_COMMUNITY_OBJECT_BINDINGS_V1: usize = 2048;
/// Maximum CAU1 decision rows.
pub const MAX_COMMUNITY_DECISION_ROWS_V1: usize = 2048;
const MAX_EVIDENCE: usize = 1_048_576;
/// `[COW1, ARD1 digest, ARD1 registration]`: array head and three hashes.
const OBJECT_ROW_BYTES: usize = 1 + 3 * 34;
// Upper bound of a CAU1, a plain literal so no arithmetic mutant survives
// in it: fixed fields and heads under 512 bytes, 2048 object rows of 103
// bytes and 2048 decision rows of at most 172 bytes (array head 1, four
// hashes 136, T 17 and two nine-byte heads).
const MAX_ENCODED_BYTES: usize = 563_712;
const _: () = assert!(MAX_COMMUNITY_OBJECT_BINDINGS_V1 == 2048);
const _: () = assert!(MAX_COMMUNITY_DECISION_ROWS_V1 == 2048);
const _: () = assert!(MAX_ENCODED_BYTES < MAX_EVIDENCE);

/// One admitted object: `[COW1_physical_address, ARD1_artifact_digest,
/// ARD1_registration_address]`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct CommunityObjectBindingV1 {
    /// Physical COW1 address.
    pub object_address: Hash,
    /// ARD1 artifact digest.
    pub artifact_digest: Hash,
    /// ARD1 registration address.
    pub registration_address: Hash,
}

/// One evaluated CAU1 decision row.
///
/// `[AUD1_digest, request_digest, leaf_grant_id, authority_T, head_seq,
/// revocation_epoch, policy_revision]`. Field order is the sort order: rows
/// are strictly ascending by the whole tuple.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct CommunityDecisionRowV1 {
    /// BLAKE3-256 of the canonical AUD1.
    pub decision_digest: Hash,
    /// `AuthorizationRequestV1::binding_digest` of the evaluated request.
    pub request_digest: Hash,
    /// The leaf grant the decision evaluated.
    pub leaf_grant_id: Hash,
    /// The leaf's authority Timeline.
    pub authority_timeline: TimelineId,
    /// That Timeline's persisted authority head at evaluation.
    pub head_seq: u64,
    /// That Timeline's revocation epoch at evaluation.
    pub revocation_epoch: u64,
    /// The capability policy revision evaluated.
    pub policy_revision: Hash,
}

/// `[reservation_id, reservation_sample_micros, decision_bound_micros]`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityClockBoundV1 {
    /// Positive trusted-clock reservation sequence.
    pub reservation_id: u64,
    /// The reservation's trusted sample.
    pub reservation_sample_micros: u64,
    /// The operation's decision bound, after the sample.
    pub decision_bound_micros: u64,
}

/// Untrusted CAU1 fields.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityAuthorityEvidenceInputV1 {
    /// Nonzero protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Execution Timeline; the child T for Fork.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// ADR-128 operation kind and identity.
    pub operation: CommunityArtifactOperationV1,
    /// Prepared CIN1/input-set digest, or the full CGI1/CGC1/CQC1 digest.
    pub input_identity: Hash,
    /// At most 2048 rows, strictly ascending by the whole triple.
    pub object_bindings: Vec<CommunityObjectBindingV1>,
    /// Inventory generation the verifier read.
    pub inventory_generation: u64,
    /// H(CAV1) of the current view the verifier read.
    pub current_premise_digest: Hash,
    /// 1..2048 rows, strictly ascending by the whole tuple.
    pub decision_rows: Vec<CommunityDecisionRowV1>,
    /// Admitted worker/cell/recording recipient digest.
    pub recipient_identity_digest: Hash,
    /// Trusted-clock reservation and decision bound.
    pub clock_bound: CommunityClockBoundV1,
    /// Original positive evidence horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact fifteen-field CAU1.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityAuthorityEvidenceV1(CommunityAuthorityEvidenceInputV1);

impl CommunityAuthorityEvidenceV1 {
    /// Validate local identities, row order and bounds.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for more than 2048 object rows, zero or more
    /// than 2048 decision rows, or an invalid horizon; `InvalidBinding` for a
    /// zero identity, digest or reservation, unordered or repeated rows, a
    /// decision bound not after its reservation sample, or a pass key for
    /// another Timeline/generation.
    pub fn new(input: CommunityAuthorityEvidenceInputV1) -> Result<Self> {
        if input.object_bindings.len() > MAX_COMMUNITY_OBJECT_BINDINGS_V1
            || !(1..=MAX_COMMUNITY_DECISION_ROWS_V1).contains(&input.decision_rows.len())
        {
            return Err(Error::BoundsExceeded);
        }
        let clock = input.clock_bound;
        let invalid = input.store_incarnation == [0; 16]
            || [
                input.input_identity,
                input.current_premise_digest,
                input.recipient_identity_digest,
            ]
            .contains(&Hash::zero())
            || clock.reservation_id == 0
            || clock.reservation_sample_micros >= clock.decision_bound_micros
            || input.object_bindings.iter().any(|row| {
                [
                    row.object_address,
                    row.artifact_digest,
                    row.registration_address,
                ]
                .contains(&Hash::zero())
            })
            || input.decision_rows.iter().any(|row| {
                row.authority_timeline.inner().to_bytes() == [0; 16]
                    || [
                        row.decision_digest,
                        row.request_digest,
                        row.leaf_grant_id,
                        row.policy_revision,
                    ]
                    .contains(&Hash::zero())
            })
            || !input.object_bindings.is_sorted_by(|a, b| a < b)
            || !input.decision_rows.is_sorted_by(|a, b| a < b);
        if invalid {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_operation(input.operation, input.timeline, input.generation))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow the exact fields without resolving any decision or object.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityAuthorityEvidenceInputV1 {
        &self.0
    }

    /// Encode the complete preferred CAU1 into zeroizing storage sized
    /// exactly, so no reallocation leaves an unwiped copy.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(encoded_len(input)));
        record_prefix(&mut out, 15, *b"CAU1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_operation(&mut out, input.operation);
        encode_hash(&mut out, input.input_identity);
        encode_head(&mut out, 4, input.object_bindings.len() as u64);
        for row in &input.object_bindings {
            out.push(0x83);
            encode_hash(&mut out, row.object_address);
            encode_hash(&mut out, row.artifact_digest);
            encode_hash(&mut out, row.registration_address);
        }
        encode_head(&mut out, 0, input.inventory_generation);
        encode_hash(&mut out, input.current_premise_digest);
        encode_head(&mut out, 4, input.decision_rows.len() as u64);
        for row in &input.decision_rows {
            out.push(0x87);
            encode_hash(&mut out, row.decision_digest);
            encode_hash(&mut out, row.request_digest);
            encode_hash(&mut out, row.leaf_grant_id);
            encode_bytes(&mut out, &row.authority_timeline.inner().to_bytes(), 2);
            encode_head(&mut out, 0, row.head_seq);
            encode_head(&mut out, 0, row.revocation_epoch);
            encode_hash(&mut out, row.policy_revision);
        }
        encode_hash(&mut out, input.recipient_identity_digest);
        out.push(0x83);
        encode_head(&mut out, 0, input.clock_bound.reservation_id);
        encode_head(&mut out, 0, input.clock_bound.reservation_sample_micros);
        encode_head(&mut out, 0, input.clock_bound.decision_bound_micros);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// ADR-128 `CurrentAuthority` commitment, COA1's
    /// `authority_evidence_digest`; not the generic CAU1 record domain.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.CurrentAuthority.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode one complete preferred CAU1.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records, any other field count, and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_EVIDENCE, 15, *b"CAU1").and_then(|mut cursor| {
            read_body(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

/// Exact CAU1 length: framing and version (7), incarnation (17), T and G
/// (34), the operation, four hashes (4 x 34), both row arrays, the
/// inventory generation, the clock bound and the horizon.
fn encoded_len(input: &CommunityAuthorityEvidenceInputV1) -> usize {
    let clock = input.clock_bound;
    let decisions: usize = input
        .decision_rows
        .iter()
        .map(|row| 1 + 4 * 34 + 17 + head_len(row.head_seq) + head_len(row.revocation_epoch))
        .sum();
    7 + 17
        + 34
        + operation_len(input.operation)
        + 4 * 34
        + head_len(input.object_bindings.len() as u64)
        + input.object_bindings.len() * OBJECT_ROW_BYTES
        + head_len(input.inventory_generation)
        + head_len(input.decision_rows.len() as u64)
        + decisions
        + 1
        + head_len(clock.reservation_id)
        + head_len(clock.reservation_sample_micros)
        + head_len(clock.decision_bound_micros)
        + head_len(input.evidence_not_after_micros)
}

fn read_body(cursor: &mut CborCursor<'_>) -> Result<CommunityAuthorityEvidenceInputV1> {
    fixed_bytes(cursor).and_then(|store_incarnation| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_operation(cursor).and_then(|operation| {
                read_hash(cursor).and_then(|input_identity| {
                    read_vec(cursor, MAX_COMMUNITY_OBJECT_BINDINGS_V1, read_object).and_then(
                        |object_bindings| {
                            read_head(cursor, 0).and_then(|inventory_generation| {
                                read_hash(cursor).and_then(|current_premise_digest| {
                                    read_vec(cursor, MAX_COMMUNITY_DECISION_ROWS_V1, read_decision)
                                        .and_then(|decision_rows| {
                                            read_tail(cursor).map(
                                                |(recipient, clock_bound, horizon)| {
                                                    CommunityAuthorityEvidenceInputV1 {
                                                        store_incarnation,
                                                        timeline,
                                                        generation,
                                                        operation,
                                                        input_identity,
                                                        object_bindings,
                                                        inventory_generation,
                                                        current_premise_digest,
                                                        decision_rows,
                                                        recipient_identity_digest: recipient,
                                                        clock_bound,
                                                        evidence_not_after_micros: horizon,
                                                    }
                                                },
                                            )
                                        })
                                })
                            })
                        },
                    )
                })
            })
        })
    })
}

/// The recipient digest, the clock bound and the horizon.
fn read_tail(cursor: &mut CborCursor<'_>) -> Result<(Hash, CommunityClockBoundV1, u64)> {
    read_hash(cursor).and_then(|recipient| {
        cursor.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
            read_head(cursor, 0).and_then(|reservation_id| {
                read_head(cursor, 0).and_then(|reservation_sample_micros| {
                    read_head(cursor, 0).and_then(|decision_bound_micros| {
                        read_head(cursor, 0).map(|horizon| {
                            (
                                recipient,
                                CommunityClockBoundV1 {
                                    reservation_id,
                                    reservation_sample_micros,
                                    decision_bound_micros,
                                },
                                horizon,
                            )
                        })
                    })
                })
            })
        })
    })
}

fn read_object(cursor: &mut CborCursor<'_>) -> Result<CommunityObjectBindingV1> {
    cursor.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
        read_hash(cursor).and_then(|object_address| {
            read_hash(cursor).and_then(|artifact_digest| {
                read_hash(cursor).map(|registration_address| CommunityObjectBindingV1 {
                    object_address,
                    artifact_digest,
                    registration_address,
                })
            })
        })
    })
}

fn read_decision(cursor: &mut CborCursor<'_>) -> Result<CommunityDecisionRowV1> {
    cursor.fixed(&[0x87]).map_err(Error::from).and_then(|()| {
        read_hash(cursor).and_then(|decision_digest| {
            read_hash(cursor).and_then(|request_digest| {
                read_hash(cursor).and_then(|leaf_grant_id| {
                    fixed_bytes(cursor).and_then(|timeline: [u8; 16]| {
                        let authority_timeline =
                            TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline));
                        read_head(cursor, 0).and_then(|head_seq| {
                            read_head(cursor, 0).and_then(|revocation_epoch| {
                                read_hash(cursor).map(|policy_revision| CommunityDecisionRowV1 {
                                    decision_digest,
                                    request_digest,
                                    leaf_grant_id,
                                    authority_timeline,
                                    head_seq,
                                    revocation_epoch,
                                    policy_revision,
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}
