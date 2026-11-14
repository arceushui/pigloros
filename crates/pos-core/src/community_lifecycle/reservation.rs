//! Original pre-Reserve identity and its retained reservation, never a permit.

use super::{
    canonical_end, encode_coordinates, fixed_bytes, read_coordinates, read_hash, read_hashes,
    read_head, read_pass_key, record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityLifecycleErrorV1, CommunityPassKeyV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

/// Pre-Reserve fields, prepared before any pass or native producer is allocated.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityReservationRequestInputV1 {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Active admitted generation.
    pub generation: [u8; 16],
    /// Original host-selected identity used to discover a lost Reserve result.
    pub reservation_operation_id: [u8; 16],
    /// Exact complete selected predecessor CSH1.
    pub expected_head_digest: Hash,
    /// Already prepared input set; it cannot depend on the future pass key.
    pub prepared_input_set_digest: Hash,
    /// Complete admitted roster identity.
    pub roster_digest: Hash,
    /// Exact durable CDP1 policy identity.
    pub profile_digest: Hash,
    /// Current authority request, independently verified by the qualified owner.
    pub authority_request_digest: Hash,
    /// Complete already admitted source closure.
    pub source_closure_digest: Hash,
    /// Requested fixed horizon, never a renewal or live authorization grant.
    pub requested_evidence_horizon: u64,
}

/// Structural CRI1 request. Neither construction nor decoding reserves a pass.
pub struct CommunityReservationRequestV1(CommunityReservationRequestInputV1);

impl CommunityReservationRequestV1 {
    /// Validate local identities and the positive i64 evidence horizon.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero identities, or `BoundsExceeded` for
    /// an out-of-range horizon. Source/current-head checks belong to the owner.
    pub fn new(input: CommunityReservationRequestInputV1) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation).and_then(|()| {
            if input.reservation_operation_id == [0; 16]
                || [
                    input.expected_head_digest,
                    input.prepared_input_set_digest,
                    input.roster_digest,
                    input.profile_digest,
                    input.authority_request_digest,
                    input.source_closure_digest,
                ]
                .contains(&Hash::zero())
            {
                return Err(CommunityLifecycleErrorV1::InvalidBinding);
            }
            validate_horizon(input.requested_evidence_horizon).map(|()| Self(input))
        })
    }

    /// Borrow the untrusted structural request fields.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityReservationRequestInputV1 {
        &self.0
    }

    /// Encode the exact twelve-field CRI1 without a future pass coordinate.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 12, *b"CRI1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_bytes(&mut out, &input.reservation_operation_id, 2);
        for hash in [
            input.expected_head_digest,
            input.prepared_input_set_digest,
            input.roster_digest,
            input.profile_digest,
            input.authority_request_digest,
            input.source_closure_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_head(&mut out, 0, input.requested_evidence_horizon);
        out
    }

    /// Decode one whole preferred CRI1, without consulting or changing a store.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, trailing, oversized, unsupported or
    /// locally invalid records. A successful decode grants no authority.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1024, 12, *b"CRI1").and_then(|mut cursor| {
            read_request(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

/// Untrusted fields retained for the one original successful Reserve.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityReservationInputV1 {
    /// Allocated pass coordinate, independent of Event/Tick allocation.
    pub pass_key: CommunityPassKeyV1,
    /// Exact original CRI1 digest.
    pub request_digest: Hash,
    /// Positive store-wide native producer ordinal.
    pub native_producer_ordinal: u64,
    /// Complete selected predecessor CSH1 bound by the request.
    pub predecessor_head_digest: Hash,
    /// Complete admitted roster identity.
    pub roster_digest: Hash,
    /// Prepared inputs bound by the original request.
    pub prepared_input_set_digest: Hash,
    /// Exact durable CDP1 policy identity.
    pub profile_digest: Hash,
    /// Original admitted fixed horizon; discovery cannot extend it.
    pub evidence_not_after_micros: u64,
}

/// Immutable CPR1 data. Reading or reconstructing it never issues a guest permit.
pub struct CommunityReservationV1(CommunityReservationInputV1);

impl CommunityReservationV1 {
    /// Validate a retained reservation's local fields, without allocating it.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero links/native ordinal, or
    /// `BoundsExceeded` for an out-of-range evidence horizon.
    pub fn new(input: CommunityReservationInputV1) -> Result<Self> {
        if input.native_producer_ordinal == 0
            || [
                input.request_digest,
                input.predecessor_head_digest,
                input.roster_digest,
                input.prepared_input_set_digest,
                input.profile_digest,
            ]
            .contains(&Hash::zero())
        {
            return Err(CommunityLifecycleErrorV1::InvalidBinding);
        }
        validate_horizon(input.evidence_not_after_micros).map(|()| Self(input))
    }

    /// Borrow the retained fields without authenticating the original writer.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityReservationInputV1 {
        &self.0
    }

    /// Encode the exact ten-field CPR1 in a pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        record_prefix(&mut out, 10, *b"CPR1");
        let key_bytes = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &key_bytes, 2);
        encode_hash(&mut out, input.request_digest);
        encode_head(&mut out, 0, input.native_producer_ordinal);
        for hash in [
            input.predecessor_head_digest,
            input.roster_digest,
            input.prepared_input_set_digest,
            input.profile_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Decode one whole preferred CPR1 as retained data, never as a permit.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, trailing, oversized, unsupported or
    /// locally invalid records, including invalid nested CPK1 coordinates.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 512, 10, *b"CPR1").and_then(|mut cursor| {
            read_reservation(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

fn read_request(cursor: &mut CborCursor<'_>) -> Result<CommunityReservationRequestInputV1> {
    read_coordinates(cursor).and_then(|(timeline, generation)| {
        fixed_bytes(cursor).and_then(|reservation_operation_id| {
            read_hashes::<6>(cursor).and_then(
                |[expected_head_digest, prepared_input_set_digest, roster_digest, profile_digest, authority_request_digest, source_closure_digest]| {
                    read_head(cursor, 0).map(|requested_evidence_horizon| {
                        CommunityReservationRequestInputV1 {
                            timeline,
                            generation,
                            reservation_operation_id,
                            expected_head_digest,
                            prepared_input_set_digest,
                            roster_digest,
                            profile_digest,
                            authority_request_digest,
                            source_closure_digest,
                            requested_evidence_horizon,
                        }
                    })
                },
            )
        })
    })
}

fn read_reservation(cursor: &mut CborCursor<'_>) -> Result<CommunityReservationInputV1> {
    read_pass_key(cursor).and_then(|pass_key| {
        read_hash(cursor).and_then(|request_digest| {
            read_head(cursor, 0).and_then(|native_producer_ordinal| {
                read_hashes::<4>(cursor).and_then(
                    |[predecessor_head_digest, roster_digest, prepared_input_set_digest, profile_digest]| {
                        read_head(cursor, 0).map(|evidence_not_after_micros| {
                            CommunityReservationInputV1 {
                                pass_key,
                                request_digest,
                                native_producer_ordinal,
                                predecessor_head_digest,
                                roster_digest,
                                prepared_input_set_digest,
                                profile_digest,
                                evidence_not_after_micros,
                            }
                        })
                    },
                )
            })
        })
    })
}
