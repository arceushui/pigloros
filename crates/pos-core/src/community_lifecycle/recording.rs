//! Complete CRR1 Replay root, checked against the exact due roster and CIV1s.

use super::{
    canonical_end, read_hash, read_head, read_pass_key, record_cursor, record_prefix,
    validate_horizon, CommunityInvocationEvidenceV1, CommunityLifecycleErrorV1 as Error,
    CommunityPassKeyV1, Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

/// Closed presentation-only omission reasons; none can replace base recording.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityAnnotationOmissionV1 {
    /// Code0.
    UnsupportedClaimSchema,
    /// Code1.
    InvalidClaim,
    /// Code2.
    UnresolvedAnnotationInput,
    /// Code3.
    AnnotationBudget,
    /// Code4.
    AnnotationPolicy,
}

impl CommunityAnnotationOmissionV1 {
    const fn code(self) -> u8 {
        match self {
            Self::UnsupportedClaimSchema => 0,
            Self::InvalidClaim => 1,
            Self::UnresolvedAnnotationInput => 2,
            Self::AnnotationBudget => 3,
            Self::AnnotationPolicy => 4,
        }
    }
}

/// A canonical set of the five closed annotation omission reasons.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityAnnotationOmissionsV1(u8);

impl CommunityAnnotationOmissionsV1 {
    /// Empty reason set; it cannot explain an omitted annotation.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Include a reason. Repeating a reason does not create duplicate wire rows.
    #[must_use]
    pub const fn with_reason(self, reason: CommunityAnnotationOmissionV1) -> Self {
        Self(self.0 | (1 << reason.code()))
    }

    /// Whether no annotation omission reason is recorded.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn codes(self) -> impl Iterator<Item = u8> {
        (0..=4_u8).filter(move |code| self.0 & (1 << code) != 0)
    }
}

/// One due member's independently selected CMB1/CNT1 identity pair.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityReplayMemberBindingV1 {
    /// Exact member binding in strict ascending CMB1 order.
    pub member_binding_digest: Hash,
    /// Exact retained execution tuple, independent of the measurement key.
    pub negotiated_tuple_digest: Hash,
}

/// Complete successful invocation evidence and its retained presentation count.
pub struct CommunityReplayMemberV1<'a> {
    /// Actual CIV1, not a caller-selected unrelated digest.
    pub invocation: &'a CommunityInvocationEvidenceV1,
    /// Number of that invocation's annotations retained in validated CAT1.
    pub retained_annotation_count: u64,
    /// Closed reasons for any presentation omissions.
    pub omissions: CommunityAnnotationOmissionsV1,
}

/// Untrusted CRR1 inputs. The owner supplies the actual complete due roster.
pub struct CommunityReplayRecordingInputV1<'a> {
    /// Original pass whose successful invocations are recorded.
    pub pass_key: CommunityPassKeyV1,
    /// Complete due CMB1/CNT1 bindings, not a roster reconstructed by omission.
    pub due_roster: &'a [CommunityReplayMemberBindingV1],
    /// Exactly one successful CIV1 and coverage entry per due member.
    pub members: &'a [CommunityReplayMemberV1<'a>],
    /// Original admitted recording horizon, not a live read permit.
    pub evidence_not_after_micros: u64,
}

/// Complete structural Replay root, still requiring guarded retained artifacts.
pub struct CommunityReplayRecordingV1<'a>(CommunityReplayRecordingInputV1<'a>);

impl<'a> CommunityReplayRecordingV1<'a> {
    /// Bind every CIV1 to the exact pass, due member and negotiated tuple.
    ///
    /// # Errors
    /// Rejects an oversized, missing, substituted, duplicate or unsorted roster;
    /// mismatched invocation bindings; inconsistent annotation counts/reasons;
    /// or an invalid horizon. Actual authority/artifact availability is owner work.
    pub fn new(input: CommunityReplayRecordingInputV1<'a>) -> Result<Self> {
        if input.due_roster.len() > MAX_COMMUNITY_MEMBERS_V1 {
            return Err(Error::BoundsExceeded);
        }
        if input.due_roster.len() != input.members.len() {
            return Err(Error::InvalidBinding);
        }
        let mut prior = None;
        let validation =
            input
                .due_roster
                .iter()
                .zip(input.members)
                .try_for_each(|(binding, member)| {
                    let evidence = member.invocation.as_input();
                    if binding.member_binding_digest == Hash::zero()
                        || binding.negotiated_tuple_digest == Hash::zero()
                        || prior.is_some_and(|previous| previous >= binding.member_binding_digest)
                        || evidence.pass_key != input.pass_key
                        || evidence.member_binding_digest != binding.member_binding_digest
                        || evidence.negotiated_tuple_digest != binding.negotiated_tuple_digest
                        || member.retained_annotation_count > evidence.validated_annotation_count
                        || (member.retained_annotation_count == evidence.validated_annotation_count)
                            != member.omissions.is_empty()
                    {
                        return Err(Error::InvalidBinding);
                    }
                    prior = Some(binding.member_binding_digest);
                    Ok(())
                });
        validation
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow the complete retained binding data, without granting Replay use.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityReplayRecordingInputV1<'a> {
        &self.0
    }

    /// Encode exact seven-field CRR1 with all arrays in the same CMB1 order.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(65_536));
        record_prefix(&mut out, 7, *b"CRR1");
        let pass_key = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &pass_key, 2);
        encode_head(&mut out, 4, input.members.len() as u64);
        for member in input.members {
            encode_hash(&mut out, member.invocation.digest());
        }
        encode_head(&mut out, 4, input.members.len() as u64);
        for member in input.members {
            encode_hash(
                &mut out,
                member.invocation.as_input().negotiated_tuple_digest,
            );
        }
        encode_head(&mut out, 4, input.members.len() as u64);
        for member in input.members {
            let evidence = member.invocation.as_input();
            out.push(0x84);
            encode_hash(&mut out, evidence.member_binding_digest);
            encode_head(&mut out, 0, evidence.validated_annotation_count);
            encode_head(&mut out, 0, member.retained_annotation_count);
            encode_head(&mut out, 4, u64::from(member.omissions.0.count_ones()));
            for code in member.omissions.codes() {
                encode_head(&mut out, 0, u64::from(code));
            }
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Derive protected Replay-root identity, not a State or execution producer.
    #[must_use]
    pub fn digest(&self) -> Hash {
        super::digest(b"PiglorOS.Community.CRR1.v1\0", &self.to_canonical_cbor())
    }

    /// Validate a retained CRR1 against complete independently supplied evidence.
    ///
    /// This deliberately cannot turn unaccompanied hashes into a complete root:
    /// the owner must load every due CIV1 and its actual CMB1/CNT1 binding.
    /// Parsing stages borrow the wire bytes; no decoded member Vec is allocated.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized records,
    /// invalid expected data, and any pass/list/member/tuple/coverage/horizon
    /// substitution. This comparison authenticates no caller-supplied evidence.
    pub fn validate_canonical_cbor(
        bytes: &[u8],
        expected: CommunityReplayRecordingInputV1<'a>,
    ) -> Result<Self> {
        record_cursor(bytes, 65_536, 7, *b"CRR1").and_then(|mut cursor| {
            Self::new(expected).and_then(|record| {
                read_pass_key(&mut cursor).and_then(|pass| {
                    if pass != record.0.pass_key {
                        return Err(Error::InvalidBinding);
                    }
                    read_recordings(&mut cursor, record.0.members)
                        .and_then(|()| read_coverage(&mut cursor, record.0.members))
                        .and_then(|()| read_head(&mut cursor, 0))
                        .and_then(|horizon| {
                            if horizon != record.0.evidence_not_after_micros {
                                return Err(Error::InvalidBinding);
                            }
                            canonical_end(&cursor).map(|()| record)
                        })
                })
            })
        })
    }
}

fn read_recordings(
    cursor: &mut CborCursor<'_>,
    members: &[CommunityReplayMemberV1<'_>],
) -> Result<()> {
    super::seal::read_list(cursor).and_then(|digests| {
        if !digests
            .iter()
            .eq(members.iter().map(|member| member.invocation.digest()))
        {
            return Err(Error::InvalidBinding);
        }
        super::seal::read_list(cursor).and_then(|tuples| {
            if tuples.iter().eq(members
                .iter()
                .map(|member| member.invocation.as_input().negotiated_tuple_digest))
            {
                Ok(())
            } else {
                Err(Error::InvalidBinding)
            }
        })
    })
}

fn read_coverage(
    cursor: &mut CborCursor<'_>,
    members: &[CommunityReplayMemberV1<'_>],
) -> Result<()> {
    read_head(cursor, 4).and_then(|count| {
        if count != members.len() as u64 {
            return Err(Error::InvalidBinding);
        }
        members.iter().try_for_each(|member| {
            cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
                read_hash(cursor).and_then(|binding| {
                    read_head(cursor, 0).and_then(|total| {
                        read_head(cursor, 0).and_then(|retained| {
                            read_omissions(cursor).and_then(|omissions| {
                                let evidence = member.invocation.as_input();
                                if binding == evidence.member_binding_digest
                                    && total == evidence.validated_annotation_count
                                    && retained == member.retained_annotation_count
                                    && omissions == member.omissions
                                {
                                    Ok(())
                                } else {
                                    Err(Error::InvalidBinding)
                                }
                            })
                        })
                    })
                })
            })
        })
    })
}

fn read_omissions(cursor: &mut CborCursor<'_>) -> Result<CommunityAnnotationOmissionsV1> {
    read_head(cursor, 4).and_then(|count| {
        if count > 5 {
            return Err(Error::BoundsExceeded);
        }
        let mut prior = None;
        (0..count).try_fold(CommunityAnnotationOmissionsV1::none(), |set, _| {
            read_head(cursor, 0).and_then(|code| {
                if prior.is_some_and(|previous| previous >= code) {
                    return Err(Error::InvalidBinding);
                }
                prior = Some(code);
                let reason = match code {
                    0 => CommunityAnnotationOmissionV1::UnsupportedClaimSchema,
                    1 => CommunityAnnotationOmissionV1::InvalidClaim,
                    2 => CommunityAnnotationOmissionV1::UnresolvedAnnotationInput,
                    3 => CommunityAnnotationOmissionV1::AnnotationBudget,
                    4 => CommunityAnnotationOmissionV1::AnnotationPolicy,
                    _ => return Err(Error::InvalidEncoding),
                };
                Ok(set.with_reason(reason))
            })
        })
    })
}
