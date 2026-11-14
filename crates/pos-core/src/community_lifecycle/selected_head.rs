//! Complete CSH1 selection; local consistency does not authenticate selection.

use super::{
    canonical_end, encode_coordinates, read_coordinates, read_hashes, read_head, read_pass_key,
    record_cursor, record_prefix, validate_coordinates, CommunityLifecycleErrorV1,
    CommunityPassKeyV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, Seq, TimelineId};
use zeroize::Zeroizing;

/// Maximum complete roster in the accepted initial community profile.
pub const MAX_COMMUNITY_MEMBERS_V1: usize = 64;

/// Pass frontier distinct from Event sequence, Tick and native producer ordinal.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityPassFrontierV1 {
    /// Admitted initial generation root; no pass zero exists.
    Initial,
    /// Last committed pass, including a state-only or executed no-op pass.
    Committed(CommunityPassKeyV1),
}

/// Exact immutable member binding and its complete mutable CMS1 identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMemberHeadV1 {
    /// Admitted CMB1 identity, used for strict ascending roster order.
    pub member_binding_digest: Hash,
    /// Complete CMS1 progress identity, not just its State revision.
    pub member_progress_digest: Hash,
}

/// A borrowed roster view; decoding never allocates a second identity buffer.
#[derive(Clone, Copy)]
pub struct CommunityMemberHeadsV1<'a>(MemberRows<'a>);

#[derive(Clone, Copy)]
enum MemberRows<'a> {
    Typed(&'a [CommunityMemberHeadV1]),
    Canonical(&'a [u8]),
}

impl<'a> CommunityMemberHeadsV1<'a> {
    /// Borrow caller-owned rows. The complete-head constructor validates them.
    #[must_use]
    pub const fn from_members(members: &'a [CommunityMemberHeadV1]) -> Self {
        Self(MemberRows::Typed(members))
    }

    /// Number of member pairs in this view.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            MemberRows::Typed(members) => members.len(),
            MemberRows::Canonical(bytes) => bytes.len() / 69,
        }
    }

    /// Whether this untrusted view is empty; a complete head refuses it.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate fixed-size pairs without cloning a heap buffer.
    pub fn iter(&self) -> impl Iterator<Item = CommunityMemberHeadV1> + '_ {
        (0..self.len()).map(|index| match self.0 {
            MemberRows::Typed(members) => members[index],
            MemberRows::Canonical(bytes) => {
                let row = &bytes[index * 69..(index + 1) * 69];
                let mut binding = [0; 32];
                let mut progress = [0; 32];
                binding.copy_from_slice(&row[3..35]);
                progress.copy_from_slice(&row[37..69]);
                CommunityMemberHeadV1 {
                    member_binding_digest: Hash::from_bytes(binding),
                    member_progress_digest: Hash::from_bytes(progress),
                }
            }
        })
    }

    /// Exact borrowed wire rows, when decoded, for owner range accounting.
    #[must_use]
    pub const fn as_canonical_rows(&self) -> Option<&'a [u8]> {
        match self.0 {
            MemberRows::Typed(_) => None,
            MemberRows::Canonical(bytes) => Some(bytes),
        }
    }
}

impl PartialEq for CommunityMemberHeadsV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for CommunityMemberHeadsV1<'_> {}

/// Untrusted complete-head fields; the writer verifies complete roster coverage.
#[derive(Eq, PartialEq)]
pub struct CommunitySelectedHeadInputV1<'a> {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Active admitted generation.
    pub generation: [u8; 16],
    /// Initial or last successfully committed pass in this exact T/G.
    pub frontier: CommunityPassFrontierV1,
    /// All members, unchanged/not-due members included, in strict digest order.
    pub member_heads: CommunityMemberHeadsV1<'a>,
    /// Existing Event logical head; zero is valid before the first Event.
    pub event_logical_head: Seq,
    /// Exact durable CDP1 policy identity.
    pub profile_digest: Hash,
    /// Complete committed host Tick/Simulation Time CST1 identity.
    pub host_progress_digest: Hash,
}

/// Complete structural CSH1; construction does not install or authorize a head.
pub struct CommunitySelectedHeadV1<'a>(CommunitySelectedHeadInputV1<'a>);

impl<'a> CommunitySelectedHeadV1<'a> {
    /// Validate coordinates, frontier binding and strict bounded member order.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero links, a foreign frontier or unordered
    /// members; `BoundsExceeded` for an empty or over-64 member roster.
    pub fn new(input: CommunitySelectedHeadInputV1<'a>) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation).and_then(|()| {
            validate_frontier(input.frontier, input.timeline, input.generation)
                .and_then(|()| validate_members(&input.member_heads))
                .and_then(|()| {
                    if [input.profile_digest, input.host_progress_digest].contains(&Hash::zero()) {
                        Err(CommunityLifecycleErrorV1::InvalidBinding)
                    } else {
                        Ok(Self(input))
                    }
                })
        })
    }

    /// Borrow complete structural fields without authenticating their sources.
    #[must_use]
    pub const fn as_input(&self) -> &CommunitySelectedHeadInputV1<'a> {
        &self.0
    }

    /// Encode all nine CSH1 fields in a pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(65_536));
        record_prefix(&mut out, 9, *b"CSH1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_frontier(&mut out, input.frontier);
        encode_head(&mut out, 4, input.member_heads.len() as u64);
        for member in input.member_heads.iter() {
            out.push(0x82);
            encode_hash(&mut out, member.member_binding_digest);
            encode_hash(&mut out, member.member_progress_digest);
        }
        encode_head(&mut out, 0, input.event_logical_head.as_u64());
        encode_hash(&mut out, input.profile_digest);
        encode_hash(&mut out, input.host_progress_digest);
        out
    }

    /// Decode one whole preferred CSH1 with bounded allocation and local checks.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, trailing, oversized, unsupported or
    /// locally inconsistent records. Complete live roster/source checks remain
    /// mandatory at the qualified owner, independently of this decoder.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, 65_536, 9, *b"CSH1").and_then(|mut cursor| {
            read_selected_head(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

fn validate_frontier(
    frontier: CommunityPassFrontierV1,
    timeline: TimelineId,
    generation: [u8; 16],
) -> Result<()> {
    match frontier {
        CommunityPassFrontierV1::Committed(key)
            if key.timeline() != timeline || key.generation() != generation =>
        {
            Err(CommunityLifecycleErrorV1::InvalidBinding)
        }
        CommunityPassFrontierV1::Initial | CommunityPassFrontierV1::Committed(_) => Ok(()),
    }
}

fn validate_members(members: &CommunityMemberHeadsV1<'_>) -> Result<()> {
    if members.is_empty() || members.len() > MAX_COMMUNITY_MEMBERS_V1 {
        return Err(CommunityLifecycleErrorV1::BoundsExceeded);
    }
    let mut prior = None;
    members.iter().try_for_each(|member| {
        if [member.member_binding_digest, member.member_progress_digest].contains(&Hash::zero())
            || prior.is_some_and(|digest: Hash| {
                digest.as_bytes() >= member.member_binding_digest.as_bytes()
            })
        {
            return Err(CommunityLifecycleErrorV1::InvalidBinding);
        }
        prior = Some(member.member_binding_digest);
        Ok(())
    })
}

fn encode_frontier(out: &mut Vec<u8>, frontier: CommunityPassFrontierV1) {
    match frontier {
        CommunityPassFrontierV1::Initial => out.extend_from_slice(&[0x81, 0]),
        CommunityPassFrontierV1::Committed(key) => {
            out.extend_from_slice(&[0x82, 1]);
            let key_bytes = Zeroizing::new(key.to_canonical_cbor());
            encode_bytes(out, &key_bytes, 2);
        }
    }
}

fn read_frontier(cursor: &mut CborCursor<'_>) -> Result<CommunityPassFrontierV1> {
    read_head(cursor, 4).and_then(|fields| {
        read_head(cursor, 0).and_then(|tag| match (fields, tag) {
            (1, 0) => Ok(CommunityPassFrontierV1::Initial),
            (2, 1) => read_pass_key(cursor).map(CommunityPassFrontierV1::Committed),
            _ => Err(CommunityLifecycleErrorV1::InvalidEncoding),
        })
    })
}

fn read_members<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityMemberHeadsV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count == 0 || count > MAX_COMMUNITY_MEMBERS_V1 {
            return Err(CommunityLifecycleErrorV1::BoundsExceeded);
        }
        // Each preferred pair is exactly 0x82, 0x58 0x20, hash32,
        // 0x58 0x20, hash32. The bounded count makes multiplication safe.
        cursor
            .take(count * 69)
            .map_err(CommunityLifecycleErrorV1::from)
            .and_then(|bytes| {
                if bytes
                    .chunks_exact(69)
                    .any(|row| row[..3] != [0x82, 0x58, 0x20] || row[35..37] != [0x58, 0x20])
                {
                    Err(CommunityLifecycleErrorV1::InvalidEncoding)
                } else {
                    Ok(CommunityMemberHeadsV1(MemberRows::Canonical(bytes)))
                }
            })
    })
}

fn read_selected_head<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunitySelectedHeadInputV1<'a>> {
    read_coordinates(cursor).and_then(|(timeline, generation)| {
        read_frontier(cursor).and_then(|frontier| {
            read_members(cursor).and_then(|member_heads| {
                read_head(cursor, 0).and_then(|event_logical_head| {
                    read_hashes::<2>(cursor).map(|[profile_digest, host_progress_digest]| {
                        CommunitySelectedHeadInputV1 {
                            timeline,
                            generation,
                            frontier,
                            member_heads,
                            event_logical_head: Seq::from_u64(event_logical_head),
                            profile_digest,
                            host_progress_digest,
                        }
                    })
                })
            })
        })
    })
}
