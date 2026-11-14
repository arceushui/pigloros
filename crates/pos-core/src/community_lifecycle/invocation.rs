//! Complete successful CIV1 measurements; evidence never issues an invocation.

use super::{
    canonical_end, digest, fixed_bytes, read_hash, read_hashes, read_head, read_pass_key,
    record_cursor, record_prefix, CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

/// Deterministic resource use of one completed community invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeteringV1 {
    /// Fuel consumed while instantiating the Component.
    pub startup_fuel: u64,
    /// Fuel consumed by the call itself.
    pub call_fuel: u64,
    /// Linear memory reserved across all Component memories, in bytes.
    pub memory_bytes: u64,
    /// Actual `host-v1` calls made.
    pub host_calls: u64,
}

/// Complete validated output usage, without guest payload or operational logs.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityOutputUsageV1 {
    /// Number of validated Event drafts, including zero for a State-only pass.
    pub event_count: u64,
    /// Sum of validated Event payload lengths, not canonical envelope sizes.
    pub event_payload_bytes: u64,
    /// Exact next-State byte length, not its CSC1 encoding length.
    pub state_bytes: u64,
}

/// Untrusted successful CIV1 fields. The owner compares actual CIN1/CNT1/output.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityInvocationEvidenceInputV1 {
    /// Original reserved pass, not a factual Tick.
    pub pass_key: CommunityPassKeyV1,
    /// Exact admitted CMB1.
    pub member_binding_digest: Hash,
    /// Actual fresh nonzero 16-byte invocation identity prepared before Reserve.
    pub invocation_id: [u8; 16],
    /// Exact complete CNT1 including all eight effective limits.
    pub negotiated_tuple_digest: Hash,
    /// Already prepared CIN1, independent of this later evidence identity.
    pub prepared_invocation_digest: Hash,
    /// Existing full ADR-061 V1 output digest, not a new hash definition.
    pub validated_output_digest: Hash,
    /// All four actual counters; never optional or invented for success.
    pub metering: MeteringV1,
    /// All three actual output measurements.
    pub output_usage: CommunityOutputUsageV1,
    /// Validated guest annotation count, distinct from the retained subset.
    pub validated_annotation_count: u64,
    /// Exact next-State CSC1 logical identity.
    pub next_state_content_digest: Hash,
    /// Exact Event-draft vector digest, including the existing empty-vector hash.
    pub event_draft_vector_digest: Hash,
}

/// Successful Replay evidence, not a State producer or a source of permission.
pub struct CommunityInvocationEvidenceV1(CommunityInvocationEvidenceInputV1);

impl CommunityInvocationEvidenceV1 {
    /// Check required identities. Measurements are retained without truncation.
    ///
    /// # Errors
    /// Rejects zero identities. Effective-limit, measurement and output equality
    /// must be checked against the actual validated invocation by the owner.
    /// This constructor cannot certify a caller's counters or claimed success.
    pub fn new(input: CommunityInvocationEvidenceInputV1) -> Result<Self> {
        if input.invocation_id == [0; 16]
            || [
                input.member_binding_digest,
                input.negotiated_tuple_digest,
                input.prepared_invocation_digest,
                input.validated_output_digest,
                input.next_state_content_digest,
                input.event_draft_vector_digest,
            ]
            .contains(&Hash::zero())
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self(input))
        }
    }

    /// Borrow historical data; current authority and actual measurements remain
    /// independently unverified.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityInvocationEvidenceInputV1 {
        &self.0
    }

    /// Encode exact 15-field CIV1 with two required null failure fields.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        record_prefix(&mut out, 15, *b"CIV1");
        let key = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &key, 2);
        encode_hash(&mut out, input.member_binding_digest);
        encode_bytes(&mut out, &input.invocation_id, 2);
        for hash in [
            input.negotiated_tuple_digest,
            input.prepared_invocation_digest,
            input.validated_output_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        out.push(0x84);
        for count in [
            input.metering.startup_fuel,
            input.metering.call_fuel,
            input.metering.memory_bytes,
            input.metering.host_calls,
        ] {
            encode_head(&mut out, 0, count);
        }
        out.push(0x83);
        for count in [
            input.output_usage.event_count,
            input.output_usage.event_payload_bytes,
            input.output_usage.state_bytes,
        ] {
            encode_head(&mut out, 0, count);
        }
        out.extend_from_slice(&[0xf6, 0xf6]);
        encode_head(&mut out, 0, input.validated_annotation_count);
        encode_hash(&mut out, input.next_state_content_digest);
        encode_hash(&mut out, input.event_draft_vector_digest);
        out
    }

    /// Derive protected logical CIV1 identity, never a State dependency source.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CIV1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode a complete successful record, requiring all seven measurements.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/oversized/versioned data, zero
    /// links, null/incomplete measurements or either nonnull failure field.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 4096, 15, *b"CIV1").and_then(|mut cursor| {
            read_identity(&mut cursor).and_then(|identity| {
                read_metering(&mut cursor).and_then(|metering| {
                    read_usage(&mut cursor).and_then(|output_usage| {
                        read_success_tail(&mut cursor).and_then(|(count, next_state, drafts)| {
                            let [negotiated_tuple_digest, prepared_invocation_digest, validated_output_digest] = identity.digests;
                            let input = CommunityInvocationEvidenceInputV1 {
                                pass_key: identity.pass_key,
                                member_binding_digest: identity.member,
                                invocation_id: identity.invocation,
                                negotiated_tuple_digest, prepared_invocation_digest, validated_output_digest,
                                metering, output_usage, validated_annotation_count: count,
                                next_state_content_digest: next_state, event_draft_vector_digest: drafts,
                            };
                            canonical_end(&cursor).and_then(|()| Self::new(input))
                        })
                    })
                })
            })
        })
    }
}

struct InvocationIdentity {
    pass_key: CommunityPassKeyV1,
    member: Hash,
    invocation: [u8; 16],
    digests: [Hash; 3],
}

fn read_identity(cursor: &mut CborCursor<'_>) -> Result<InvocationIdentity> {
    read_pass_key(cursor).and_then(|pass_key| {
        read_hash(cursor).and_then(|member| {
            fixed_bytes(cursor).and_then(|invocation| {
                read_hashes(cursor).map(|digests| InvocationIdentity {
                    pass_key,
                    member,
                    invocation,
                    digests,
                })
            })
        })
    })
}

fn read_unsigned_array<const N: usize>(cursor: &mut CborCursor<'_>) -> Result<[u64; N]> {
    read_head(cursor, 4).and_then(|count| {
        if count != N as u64 {
            return Err(Error::InvalidEncoding);
        }
        let mut values = [0; N];
        values
            .iter_mut()
            .try_for_each(|value| read_head(cursor, 0).map(|parsed| *value = parsed))
            .map(|()| values)
    })
}

fn read_metering(cursor: &mut CborCursor<'_>) -> Result<MeteringV1> {
    read_unsigned_array(cursor).map(|[startup_fuel, call_fuel, memory_bytes, host_calls]| {
        MeteringV1 {
            startup_fuel,
            call_fuel,
            memory_bytes,
            host_calls,
        }
    })
}

fn read_usage(cursor: &mut CborCursor<'_>) -> Result<CommunityOutputUsageV1> {
    read_unsigned_array(cursor).map(|[event_count, event_payload_bytes, state_bytes]| {
        CommunityOutputUsageV1 {
            event_count,
            event_payload_bytes,
            state_bytes,
        }
    })
}

fn read_success_tail(cursor: &mut CborCursor<'_>) -> Result<(u64, Hash, Hash)> {
    cursor
        .fixed(&[0xf6, 0xf6])
        .map_err(Error::from)
        .and_then(|()| read_head(cursor, 0))
        .and_then(|count| read_hashes(cursor).map(|[state, drafts]| (count, state, drafts)))
}
