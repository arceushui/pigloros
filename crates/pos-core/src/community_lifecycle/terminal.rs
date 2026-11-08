//! Retained terminal outcomes. A decoded receipt is never a Commit/Abort grant.

use super::{
    canonical_end, encode_optional_hash, read_hash, read_hashes, read_head, read_optional_hash,
    read_pass_key, record_cursor, record_prefix, validate_horizon, CommunityLifecycleErrorV1,
    CommunityPassKeyV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, Seq};
use zeroize::Zeroizing;

/// Actual committed factual allocation, absent for a zero-Event pass.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityFactualRangeV1 {
    /// Independently allocated positive factual Tick, not the pass ordinal.
    pub tick: u64,
    /// First positive logical sequence in the committed batch.
    pub first_logical_sequence: Seq,
    /// Last positive logical sequence, at least the first.
    pub last_logical_sequence: Seq,
}

/// Untrusted CPC1 fields; the qualified writer verifies the exact effect set.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityCommitInputV1 {
    /// Original reserved pass coordinate.
    pub pass_key: CommunityPassKeyV1,
    /// Original CPR1 reservation identity.
    pub reservation_digest: Hash,
    /// Exact complete successful CPS1 sealed candidate.
    pub sealed_result_digest: Hash,
    /// Complete selected CSH1 installed in the same transaction.
    pub selected_head_digest: Hash,
    /// Present exactly when at least one factual Event was committed.
    pub factual_range: Option<CommunityFactualRangeV1>,
    /// Exact CPD1, including for a state-only pass.
    pub dependency_commit_digest: Hash,
    /// Exact admitted `InventoryCommit` preimage identity.
    pub inventory_commit_digest: Hash,
    /// Original fixed admitted evidence horizon.
    pub evidence_not_after_micros: u64,
}

/// Structural committed outcome, without selection or execution authority.
pub struct CommunityCommitV1(CommunityCommitInputV1);

impl CommunityCommitV1 {
    /// Check required links, factual range shape and the fixed horizon.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero links or an invalid factual range;
    /// `BoundsExceeded` for an out-of-range evidence horizon.
    pub fn new(input: CommunityCommitInputV1) -> Result<Self> {
        if [
            input.reservation_digest,
            input.sealed_result_digest,
            input.selected_head_digest,
            input.dependency_commit_digest,
            input.inventory_commit_digest,
        ]
        .contains(&Hash::zero())
        {
            return Err(CommunityLifecycleErrorV1::InvalidBinding);
        }
        validate_factual_range(input.factual_range)
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow retained fields; authenticity/current selection are not implied.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityCommitInputV1 {
        &self.0
    }

    /// Encode the exact ten-field CPC1 in a pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 10, *b"CPC1");
        let key_bytes = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &key_bytes, 2);
        for hash in [
            input.reservation_digest,
            input.sealed_result_digest,
            input.selected_head_digest,
        ] {
            encode_hash(&mut out, hash);
        }
        encode_factual_range(&mut out, input.factual_range);
        encode_hash(&mut out, input.dependency_commit_digest);
        encode_hash(&mut out, input.inventory_commit_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Decode one preferred CPC1 without committing or reselecting anything.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, trailing, oversized, unsupported or
    /// locally invalid records, including invalid nested pass coordinates.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1024, 10, *b"CPC1").and_then(|mut cursor| {
            read_commit(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

/// Closed CAB1 reason codes. None establishes the required host admission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityAbortReasonV1 {
    /// Code0; requires the installed cancellation authority and current fence.
    AuthenticatedCancellation,
    /// Code1; requires the exact validated invocation failure evidence.
    ValidatedInvocationFailure,
    /// Code2; requires exact host-owned admission decision evidence.
    AdmissionRefused,
    /// Code3; requires exact host-owned protected-use decision evidence.
    ProtectedUseRefused,
    /// Code4; requires the installed retirement authority and current fence.
    RetiringGeneration,
}

/// Untrusted CAB1 fields; no absent-row or expiry read supplies an Abort.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityAbortInputV1 {
    /// Original reserved pass coordinate.
    pub pass_key: CommunityPassKeyV1,
    /// Exact original CPR1.
    pub reservation_digest: Hash,
    /// Original sealed candidate, if Seal completed before Abort.
    pub sealed_result_digest: Option<Hash>,
    /// Closed reason interpreted by the independently admitted host control.
    pub reason: CommunityAbortReasonV1,
    /// Required exact failure/host-decision CFO1 for reasons1,2,3.
    pub failure_evidence_digest: Option<Hash>,
    /// Exact complete quarantine delta when required by the failure policy.
    pub quarantine_delta_digest: Option<Hash>,
    /// Original fixed admitted evidence horizon, never renewed by discovery.
    pub evidence_not_after_micros: u64,
}

/// Structural aborted outcome. It cannot cancel a pass or issue a new permit.
pub struct CommunityAbortV1(CommunityAbortInputV1);

impl CommunityAbortV1 {
    /// Check local identities, reason/evidence shape and the fixed horizon.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero links or missing required evidence;
    /// `BoundsExceeded` for an out-of-range evidence horizon.
    pub fn new(input: CommunityAbortInputV1) -> Result<Self> {
        if input.reservation_digest == Hash::zero()
            || [
                input.sealed_result_digest,
                input.failure_evidence_digest,
                input.quarantine_delta_digest,
            ]
            .contains(&Some(Hash::zero()))
            || (matches!(
                input.reason,
                CommunityAbortReasonV1::ValidatedInvocationFailure
                    | CommunityAbortReasonV1::AdmissionRefused
                    | CommunityAbortReasonV1::ProtectedUseRefused
            ) && input.failure_evidence_digest.is_none())
        {
            return Err(CommunityLifecycleErrorV1::InvalidBinding);
        }
        validate_horizon(input.evidence_not_after_micros).map(|()| Self(input))
    }

    /// Borrow the retained exact terminal-request tuple as untrusted data.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityAbortInputV1 {
        &self.0
    }

    /// Encode the exact nine-field CAB1 in a pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 9, *b"CAB1");
        let key_bytes = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &key_bytes, 2);
        encode_hash(&mut out, input.reservation_digest);
        encode_optional_hash(&mut out, input.sealed_result_digest);
        let reason = match input.reason {
            CommunityAbortReasonV1::AuthenticatedCancellation => 0,
            CommunityAbortReasonV1::ValidatedInvocationFailure => 1,
            CommunityAbortReasonV1::AdmissionRefused => 2,
            CommunityAbortReasonV1::ProtectedUseRefused => 3,
            CommunityAbortReasonV1::RetiringGeneration => 4,
        };
        encode_head(&mut out, 0, reason);
        encode_optional_hash(&mut out, input.failure_evidence_digest);
        encode_optional_hash(&mut out, input.quarantine_delta_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Decode one preferred CAB1 without performing any control operation.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, trailing, oversized, unsupported or
    /// locally invalid records, unknown reasons and missing required evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1024, 9, *b"CAB1").and_then(|mut cursor| {
            read_abort(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

fn validate_factual_range(range: Option<CommunityFactualRangeV1>) -> Result<()> {
    if range.is_some_and(|range| {
        range.tick == 0
            || range.first_logical_sequence == Seq::ZERO
            || range.first_logical_sequence > range.last_logical_sequence
    }) {
        Err(CommunityLifecycleErrorV1::InvalidBinding)
    } else {
        Ok(())
    }
}

fn encode_factual_range(out: &mut Vec<u8>, range: Option<CommunityFactualRangeV1>) {
    match range {
        None => out.push(0xf6),
        Some(range) => {
            out.push(0x83);
            encode_head(out, 0, range.tick);
            encode_head(out, 0, range.first_logical_sequence.as_u64());
            encode_head(out, 0, range.last_logical_sequence.as_u64());
        }
    }
}

fn read_factual_range(cursor: &mut CborCursor<'_>) -> Result<Option<CommunityFactualRangeV1>> {
    if cursor.consume_if(0xf6) {
        return Ok(None);
    }
    cursor
        .fixed(&[0x83])
        .map_err(CommunityLifecycleErrorV1::from)
        .and_then(|()| {
            read_head(cursor, 0).and_then(|tick| {
                read_head(cursor, 0).and_then(|first| {
                    read_head(cursor, 0).map(|last| {
                        Some(CommunityFactualRangeV1 {
                            tick,
                            first_logical_sequence: Seq::from_u64(first),
                            last_logical_sequence: Seq::from_u64(last),
                        })
                    })
                })
            })
        })
}

fn read_commit(cursor: &mut CborCursor<'_>) -> Result<CommunityCommitInputV1> {
    read_pass_key(cursor).and_then(|pass_key| {
        read_hashes::<3>(cursor).and_then(
            |[reservation_digest, sealed_result_digest, selected_head_digest]| {
                read_factual_range(cursor).and_then(|factual_range| {
                    read_hashes::<2>(cursor).and_then(
                        |[dependency_commit_digest, inventory_commit_digest]| {
                            read_head(cursor, 0).map(|evidence_not_after_micros| {
                                CommunityCommitInputV1 {
                                    pass_key,
                                    reservation_digest,
                                    sealed_result_digest,
                                    selected_head_digest,
                                    factual_range,
                                    dependency_commit_digest,
                                    inventory_commit_digest,
                                    evidence_not_after_micros,
                                }
                            })
                        },
                    )
                })
            },
        )
    })
}

fn read_abort_reason(cursor: &mut CborCursor<'_>) -> Result<CommunityAbortReasonV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(CommunityAbortReasonV1::AuthenticatedCancellation),
        1 => Ok(CommunityAbortReasonV1::ValidatedInvocationFailure),
        2 => Ok(CommunityAbortReasonV1::AdmissionRefused),
        3 => Ok(CommunityAbortReasonV1::ProtectedUseRefused),
        4 => Ok(CommunityAbortReasonV1::RetiringGeneration),
        _ => Err(CommunityLifecycleErrorV1::InvalidEncoding),
    })
}

fn read_abort(cursor: &mut CborCursor<'_>) -> Result<CommunityAbortInputV1> {
    read_pass_key(cursor).and_then(|pass_key| {
        read_hash(cursor).and_then(|reservation_digest| {
            read_optional_hash(cursor).and_then(|sealed_result_digest| {
                read_abort_reason(cursor).and_then(|reason| {
                    read_optional_hash(cursor).and_then(|failure_evidence_digest| {
                        read_optional_hash(cursor).and_then(|quarantine_delta_digest| {
                            read_head(cursor, 0).map(|evidence_not_after_micros| {
                                CommunityAbortInputV1 {
                                    pass_key,
                                    reservation_digest,
                                    sealed_result_digest,
                                    reason,
                                    failure_evidence_digest,
                                    quarantine_delta_digest,
                                    evidence_not_after_micros,
                                }
                            })
                        })
                    })
                })
            })
        })
    })
}
