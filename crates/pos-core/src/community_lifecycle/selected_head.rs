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

/// Untrusted complete-head fields; the writer verifies complete roster coverage.
#[derive(Eq, PartialEq)]
pub struct CommunitySelectedHeadInputV1 {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Active admitted generation.
    pub generation: [u8; 16],
    /// Initial or last successfully committed pass in this exact T/G.
    pub frontier: CommunityPassFrontierV1,
    /// All members, unchanged/not-due members included, in strict digest order.
    pub member_heads: Vec<CommunityMemberHeadV1>,
    /// Existing Event logical head; zero is valid before the first Event.
    pub event_logical_head: Seq,
    /// Exact durable CDP1 policy identity.
    pub profile_digest: Hash,
    /// Complete committed host Tick/Simulation Time CST1 identity.
    pub host_progress_digest: Hash,
}

/// Complete structural CSH1; construction does not install or authorize a head.
pub struct CommunitySelectedHeadV1(CommunitySelectedHeadInputV1);

impl CommunitySelectedHeadV1 {
    /// Validate coordinates, frontier binding and strict bounded member order.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero links, a foreign frontier or unordered
    /// members; `BoundsExceeded` for an empty or over-64 member roster.
    pub fn new(input: CommunitySelectedHeadInputV1) -> Result<Self> {
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
    pub const fn as_input(&self) -> &CommunitySelectedHeadInputV1 {
        &self.0
    }

    /// Encode all nine CSH1 fields in a pre-sized zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(65_536));
        record_prefix(&mut out, 9, b"CSH1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_frontier(&mut out, input.frontier);
        encode_head(&mut out, 4, input.member_heads.len() as u64);
        for member in &input.member_heads {
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
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 65_536, 9, b"CSH1").and_then(|mut cursor| {
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

fn validate_members(members: &[CommunityMemberHeadV1]) -> Result<()> {
    if members.is_empty() || members.len() > MAX_COMMUNITY_MEMBERS_V1 {
        return Err(CommunityLifecycleErrorV1::BoundsExceeded);
    }
    if members.iter().any(|member| {
        [member.member_binding_digest, member.member_progress_digest].contains(&Hash::zero())
    }) || members.windows(2).any(|pair| {
        pair[0].member_binding_digest.as_bytes() >= pair[1].member_binding_digest.as_bytes()
    }) {
        Err(CommunityLifecycleErrorV1::InvalidBinding)
    } else {
        Ok(())
    }
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

fn read_members(cursor: &mut CborCursor<'_>) -> Result<Vec<CommunityMemberHeadV1>> {
    read_head(cursor, 4).and_then(|count| {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count == 0 || count > MAX_COMMUNITY_MEMBERS_V1 {
            return Err(CommunityLifecycleErrorV1::BoundsExceeded);
        }
        let mut members = Vec::with_capacity(count);
        (0..count)
            .try_for_each(|_| {
                cursor
                    .fixed(&[0x82])
                    .map_err(CommunityLifecycleErrorV1::from)
                    .and_then(|()| read_hashes::<2>(cursor))
                    .map(|[member_binding_digest, member_progress_digest]| {
                        members.push(CommunityMemberHeadV1 {
                            member_binding_digest,
                            member_progress_digest,
                        });
                    })
            })
            .map(|()| members)
    })
}

fn read_selected_head(cursor: &mut CborCursor<'_>) -> Result<CommunitySelectedHeadInputV1> {
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
