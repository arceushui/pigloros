//! Exact minimal CSM1 scope cover. Opaque references never resolve authority.

use super::{
    canonical_end, digest, encode_coordinates, fixed_bytes, head_len, read_coordinates, read_hash,
    read_head, record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

/// Maximum complete actual scope-member set in the selected profile.
pub const MAX_COMMUNITY_SCOPE_MEMBERS_V1: usize = 2048;
pub(super) const MAX_SCOPE_ENCODING: usize = 128 + MAX_COMMUNITY_SCOPE_MEMBERS_V1 * 129;
const _: () = assert!(MAX_SCOPE_ENCODING < 1_048_576);
type ScopeKey = (Hash, [u8; 16], Hash, Hash);

/// Exact opaque scope/owner/lease row, without a plaintext value identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityScopeMemberV1 {
    /// Existing scope reference, never a synthetic subject ID.
    pub scope_reference: Hash,
    /// Actual source Timeline.
    pub source_timeline: TimelineId,
    /// Independently registered source owner reference.
    pub owner_reference: Hash,
    /// Exact original retention lease reference.
    pub retention_lease_reference: Hash,
    /// Original source-scope deadline, not a sliding lease.
    pub not_after_micros: u64,
}

impl CommunityScopeMemberV1 {
    const fn key(self) -> ScopeKey {
        (
            self.scope_reference,
            self.source_timeline.inner().to_bytes(),
            self.owner_reference,
            self.retention_lease_reference,
        )
    }
}

/// Borrowed actual scope rows; construction of the cover checks order/bounds.
#[derive(Clone, Copy)]
pub struct CommunityScopeMembersV1<'a>(ScopeRows<'a>);

#[derive(Clone, Copy)]
enum ScopeRows<'a> {
    Typed(&'a [CommunityScopeMemberV1]),
    Canonical { bytes: &'a [u8], count: usize },
}

impl<'a> CommunityScopeMembersV1<'a> {
    /// Borrow untrusted rows without allocating a second metadata set.
    #[must_use]
    pub const fn from_members(members: &'a [CommunityScopeMemberV1]) -> Self {
        Self(ScopeRows::Typed(members))
    }

    /// Exact row count; cover admission rejects more than 2048.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            ScopeRows::Typed(rows) => rows.len(),
            ScopeRows::Canonical { count, .. } => count,
        }
    }

    /// Whether no scope rows were supplied; this does not prove a public source.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate original rows without cloning a metadata buffer.
    pub fn iter(&self) -> CommunityScopeMembersIterV1<'a> {
        match self.0 {
            ScopeRows::Typed(rows) => {
                CommunityScopeMembersIterV1(ScopeIteration::Typed(rows.iter()))
            }
            ScopeRows::Canonical { bytes, count } => {
                CommunityScopeMembersIterV1(ScopeIteration::Canonical {
                    cursor: CborCursor::new(bytes),
                    remaining: count,
                })
            }
        }
    }

    /// Exact borrowed encoded rows, when decoded, for owner copy accounting.
    #[must_use]
    pub const fn as_canonical_rows(&self) -> Option<&'a [u8]> {
        match self.0 {
            ScopeRows::Typed(_) => None,
            ScopeRows::Canonical { bytes, .. } => Some(bytes),
        }
    }
}

impl<'a> IntoIterator for &CommunityScopeMembersV1<'a> {
    type Item = Result<CommunityScopeMemberV1>;
    type IntoIter = CommunityScopeMembersIterV1<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl PartialEq for CommunityScopeMembersV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityScopeMembersV1<'_> {}

/// Bounded fallible iterator over original metadata scope rows.
#[must_use]
pub struct CommunityScopeMembersIterV1<'a>(ScopeIteration<'a>);

enum ScopeIteration<'a> {
    Typed(std::slice::Iter<'a, CommunityScopeMemberV1>),
    Canonical {
        cursor: CborCursor<'a>,
        remaining: usize,
    },
}

impl Iterator for CommunityScopeMembersIterV1<'_> {
    type Item = Result<CommunityScopeMemberV1>;
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            ScopeIteration::Typed(rows) => rows.next().copied().map(Ok),
            ScopeIteration::Canonical { cursor, remaining } => {
                if *remaining == 0 {
                    None
                } else {
                    *remaining -= 1;
                    Some(read_member(cursor))
                }
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = match &self.0 {
            ScopeIteration::Typed(rows) => rows.len(),
            ScopeIteration::Canonical { remaining, .. } => *remaining,
        };
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for CommunityScopeMembersIterV1<'_> {}

/// Untrusted original metadata scope cover, not current metadata/data permission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMetadataScopeInputV1<'a> {
    /// Nonzero actual protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Real original CMA1 anchor Timeline, not a current execution substitute.
    pub metadata_anchor_timeline: TimelineId,
    /// Real original CMA1 generation, retained after its execution retirement.
    pub metadata_anchor_generation: [u8; 16],
    /// Nonzero original protection Control identity.
    pub protection_operation_id: [u8; 16],
    /// Complete scope set in strict first-four-field order.
    pub scope_members: CommunityScopeMembersV1<'a>,
    /// Independently admitted original metadata deadline.
    pub metadata_not_after_micros: u64,
}

/// CSM1 clear minimal scope cover; its visibility is not a public-data claim.
///
/// No State/record-content/value hash occurs in this grammar. Source metadata
/// retention/freeze/disposition and current service authority remain concrete
/// owner checks; row references alone cannot perform those checks.
pub struct CommunityMetadataScopeV1<'a>(CommunityMetadataScopeInputV1<'a>);

impl<'a> CommunityMetadataScopeV1<'a> {
    /// Validate local identities, bounded unique ordered rows and finite dates.
    ///
    /// # Errors
    /// Rejects zero bindings, more than 2048 rows, duplicate/unordered row keys
    /// and invalid deadlines. No source-scope or metadata lease is admitted here.
    pub fn new(input: CommunityMetadataScopeInputV1<'a>) -> Result<Self> {
        if input.scope_members.len() > MAX_COMMUNITY_SCOPE_MEMBERS_V1 {
            return Err(Error::BoundsExceeded);
        }
        if input.store_incarnation == [0; 16] || input.protection_operation_id == [0; 16] {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(
            input.metadata_anchor_timeline,
            input.metadata_anchor_generation,
        )
        .and_then(|()| validate_horizon(input.metadata_not_after_micros))
        .and_then(|()| validate_members(input.scope_members))
        .map(|()| Self(input))
    }

    /// Borrow exact original cover data without granting inspection or release.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityMetadataScopeInputV1<'a> {
        &self.0
    }

    /// Encode exact8-field CSM1 into a fully pre-sized zeroizing output buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(128 + input.scope_members.len() * 129));
        record_prefix(&mut out, 8, *b"CSM1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(
            &mut out,
            input.metadata_anchor_timeline,
            input.metadata_anchor_generation,
        );
        encode_bytes(&mut out, &input.protection_operation_id, 2);
        encode_members(&mut out, input.scope_members);
        encode_head(&mut out, 0, input.metadata_not_after_micros);
        out
    }

    /// ADR-128 `ScopeCover` commitment, not a generic CSM1 hash or an authority.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.ScopeCover.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode complete CSM1 while borrowing its original variable-width rows.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/versioned/oversized/trailing records,
    /// invalid row/order/identity/deadline bindings, without a decoded row Vec.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, 1_048_576, 8, *b"CSM1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|store_incarnation| {
                read_coordinates(&mut cursor).and_then(
                    |(metadata_anchor_timeline, metadata_anchor_generation)| {
                        fixed_bytes(&mut cursor).and_then(|protection_operation_id| {
                            read_members(&mut cursor).and_then(|scope_members| {
                                read_head(&mut cursor, 0).and_then(|metadata_not_after_micros| {
                                    canonical_end(&cursor).and_then(|()| {
                                        Self::new(CommunityMetadataScopeInputV1 {
                                            store_incarnation,
                                            metadata_anchor_timeline,
                                            metadata_anchor_generation,
                                            protection_operation_id,
                                            scope_members,
                                            metadata_not_after_micros,
                                        })
                                    })
                                })
                            })
                        })
                    },
                )
            })
        })
    }
}

fn validate_member(member: CommunityScopeMemberV1) -> Result<()> {
    if [
        member.scope_reference,
        member.owner_reference,
        member.retention_lease_reference,
    ]
    .contains(&Hash::zero())
        || member.source_timeline.inner().to_bytes() == [0; 16]
    {
        return Err(Error::InvalidBinding);
    }
    validate_horizon(member.not_after_micros)
}

pub(super) fn validate_members(members: CommunityScopeMembersV1<'_>) -> Result<()> {
    let mut previous = None;
    members.iter().try_for_each(|member| {
        member.and_then(|member| {
            validate_member(member).and_then(|()| {
                let key = member.key();
                if previous.is_some_and(|previous| previous >= key) {
                    Err(Error::InvalidBinding)
                } else {
                    previous = Some(key);
                    Ok(())
                }
            })
        })
    })
}

/// Encode the definite scope-member array, reusing decoded rows verbatim.
pub(super) fn encode_members(out: &mut Vec<u8>, members: CommunityScopeMembersV1<'_>) {
    encode_head(out, 4, members.len() as u64);
    match members.0 {
        ScopeRows::Typed(rows) => rows.iter().for_each(|member| encode_member(out, *member)),
        ScopeRows::Canonical { bytes, .. } => out.extend_from_slice(bytes),
    }
}

/// Exact length of [`encode_members`]'s array for `members`.
pub(super) fn members_len(members: CommunityScopeMembersV1<'_>) -> usize {
    head_len(members.len() as u64)
        + match members.0 {
            ScopeRows::Typed(rows) => rows
                .iter()
                .map(|member| 120 + head_len(member.not_after_micros))
                .sum::<usize>(),
            ScopeRows::Canonical { bytes, .. } => bytes.len(),
        }
}

fn encode_member(out: &mut Vec<u8>, member: CommunityScopeMemberV1) {
    out.push(0x85);
    encode_hash(out, member.scope_reference);
    encode_bytes(out, &member.source_timeline.inner().to_bytes(), 2);
    encode_hash(out, member.owner_reference);
    encode_hash(out, member.retention_lease_reference);
    encode_head(out, 0, member.not_after_micros);
}

fn read_member(cursor: &mut CborCursor<'_>) -> Result<CommunityScopeMemberV1> {
    cursor.fixed(&[0x85]).map_err(Error::from).and_then(|()| {
        read_hash(cursor).and_then(|scope_reference| {
            fixed_bytes(cursor).and_then(|source_timeline| {
                read_hash(cursor).and_then(|owner_reference| {
                    read_hash(cursor).and_then(|retention_lease_reference| {
                        read_head(cursor, 0).map(|not_after_micros| CommunityScopeMemberV1 {
                            scope_reference,
                            source_timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes(
                                source_timeline,
                            )),
                            owner_reference,
                            retention_lease_reference,
                            not_after_micros,
                        })
                    })
                })
            })
        })
    })
}

pub(super) fn read_members<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityScopeMembersV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        if count > MAX_COMMUNITY_SCOPE_MEMBERS_V1 as u64 {
            return Err(Error::BoundsExceeded);
        }
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        let mut original = cursor.clone();
        let start = cursor.position();
        (0..count)
            .try_for_each(|_| read_member(cursor).map(drop))
            .and_then(|()| {
                original
                    .take(cursor.position() - start)
                    .map_err(Error::from)
                    .map(|bytes| CommunityScopeMembersV1(ScopeRows::Canonical { bytes, count }))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        validate_members, CommunityMetadataScopeInputV1, CommunityMetadataScopeV1,
        CommunityScopeMemberV1, CommunityScopeMembersV1, Hash, ScopeRows, TimelineId,
        MAX_COMMUNITY_SCOPE_MEMBERS_V1, MAX_SCOPE_ENCODING,
    };

    #[test]
    fn maximum_scope_encoding_fits_the_enclosing_record_size_proof() -> super::Result<()> {
        let timeline = TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16]));
        let rows: Vec<_> = (1..=MAX_COMMUNITY_SCOPE_MEMBERS_V1)
            .map(|index| {
                let mut reference = [0; 32];
                reference[24..].copy_from_slice(&(index as u64).to_be_bytes());
                CommunityScopeMemberV1 {
                    scope_reference: Hash::from_bytes(reference),
                    source_timeline: timeline,
                    owner_reference: Hash::from_bytes([2; 32]),
                    retention_lease_reference: Hash::from_bytes([3; 32]),
                    not_after_micros: i64::MAX as u64,
                }
            })
            .collect();
        CommunityMetadataScopeV1::new(CommunityMetadataScopeInputV1 {
            store_incarnation: [1; 16],
            metadata_anchor_timeline: timeline,
            metadata_anchor_generation: [2; 16],
            protection_operation_id: [3; 16],
            scope_members: CommunityScopeMembersV1::from_members(&rows),
            metadata_not_after_micros: i64::MAX as u64,
        })
        .and_then(|record| {
            let encoded = record.to_canonical_cbor();
            assert!(encoded.len() <= MAX_SCOPE_ENCODING);
            CommunityMetadataScopeV1::from_canonical_cbor(&encoded)
                .map(|decoded| assert!(decoded.as_input() == record.as_input()))
        })
    }

    #[test]
    fn corrupt_internal_borrowed_rows_remain_fallible() {
        let rows = CommunityScopeMembersV1(ScopeRows::Canonical {
            bytes: &[0],
            count: 1,
        });
        assert!(validate_members(rows).is_err());
        let mut iterator = rows.iter();
        assert_eq!(iterator.size_hint(), (1, Some(1)));
        assert!(iterator.next().is_some_and(|row| row.is_err()));
        assert_eq!(iterator.size_hint(), (0, Some(0)));
        assert!(iterator.next().is_none());
    }
}
