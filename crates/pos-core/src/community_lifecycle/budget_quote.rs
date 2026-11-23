//! ADR-129 §4 CBQ1 pre-Reserve budget quote.
//!
//! CBQ1 is the forecast identity that CPV1 `budget_identity` names: the
//! exact prior shared counts, the due members' CMB1/CNT1 budgets and the
//! worst-case nodes, edges and bytes the operation may add. It excludes
//! every future CPK1/CPN1/CGR1/CPD1/CPS1/CPC1, so no
//! provenance-to-budget-to-result cycle exists. Valid bytes do not prove
//! that the counts were read from real recorded sets, and a decoded quote is
//! not checked against any limit: the concrete planner derives the quote and
//! refuses one whose maxima exceed the CDP1 shared per-record limits
//! ([`CommunityBudgetQuoteV1::require_within`]) before it mints anything.

use super::{
    canonical_end, digest, encode_coordinates, read_coordinates, read_hash, read_hashes, read_head,
    read_vec, record_cursor, record_prefix, validate_coordinates,
    CommunityLifecycleErrorV1 as Error, Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

/// Maximum canonical CBQ1 encoding.
pub const MAX_COMMUNITY_BUDGET_QUOTE_BYTES_V1: usize = 65_536;

// Fixed fields and heads stay under 256 bytes; each due row is an array
// head and two hashes (69 bytes).
const _: () = assert!(256 + MAX_COMMUNITY_MEMBERS_V1 * 69 <= MAX_COMMUNITY_BUDGET_QUOTE_BYTES_V1);

/// `[nodes, edges, declared_inputs, encoded_record_bytes]`.
///
/// These are the shared R3 counts of the actual inherited and current
/// recorded sets.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct CommunitySharedCountsV1 {
    /// Recorded nodes.
    pub nodes: u64,
    /// Recorded edges.
    pub edges: u64,
    /// Declared inputs.
    pub declared_inputs: u64,
    /// Encoded record bytes.
    pub encoded_record_bytes: u64,
}

impl CommunitySharedCountsV1 {
    pub(super) const fn values(self) -> [u64; 4] {
        [
            self.nodes,
            self.edges,
            self.declared_inputs,
            self.encoded_record_bytes,
        ]
    }
}

/// One due member's `[CMB1_digest, CNT1_digest]` budget row.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityDueMemberBudgetV1 {
    /// Admitted CMB1 identity, distinct across rows.
    pub member_binding_digest: Hash,
    /// Retained CNT1 identity whose limits bound the member.
    pub negotiated_tuple_digest: Hash,
}

/// Untrusted CBQ1 fields.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityBudgetQuoteInputV1 {
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// Exact CDP1 identity.
    pub profile_digest: Hash,
    /// Shared counts of the actual prior recorded sets.
    pub prior_shared_counts: CommunitySharedCountsV1,
    /// 1..=64 due rows with distinct CMB1 digests, in roster order.
    pub due_members: Vec<CommunityDueMemberBudgetV1>,
    /// Worst-case nodes the operation may add.
    pub maximum_required_nodes: u64,
    /// Worst-case edges the operation may add.
    pub maximum_required_edges: u64,
    /// Worst-case encoded record bytes the operation may add.
    pub maximum_required_bytes: u64,
}

/// Exact ten-field CBQ1.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityBudgetQuoteV1(CommunityBudgetQuoteInputV1);

impl CommunityBudgetQuoteV1 {
    /// Validate coordinates, the profile link and the due rows.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for no or more than 64 due rows, and
    /// `InvalidBinding` for zero coordinates or digests and a repeated CMB1
    /// digest. Roster order itself is the planner's to check.
    pub fn new(input: CommunityBudgetQuoteInputV1) -> Result<Self> {
        if !(1..=MAX_COMMUNITY_MEMBERS_V1).contains(&input.due_members.len()) {
            return Err(Error::BoundsExceeded);
        }
        let invalid = input.profile_digest == Hash::zero()
            || input.due_members.iter().any(|row| {
                [row.member_binding_digest, row.negotiated_tuple_digest].contains(&Hash::zero())
            })
            || input.due_members.iter().enumerate().any(|(index, row)| {
                input.due_members[..index]
                    .iter()
                    .any(|prior| prior.member_binding_digest == row.member_binding_digest)
            });
        if invalid {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation).map(|()| Self(input))
    }

    /// The code-0 initialization quote for `due_members`.
    ///
    /// `due_members` has one row per roster member (owner decisions on
    /// #560, notes 22722 G3 and 22729). The quote has zero prior counts,
    /// `2n` nodes and edges (one `InitialState` and one `StateRevision` CPN1
    /// per member, each with one direct input), and the caller's
    /// `maximum_required_bytes`: the planner sums each member's CNT1 State
    /// limit, CIS1 and CSR1 maxima and actual CPN1 sizes (owner decision on
    /// #560, 2026-11-19).
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn initialization(
        timeline: TimelineId,
        generation: [u8; 16],
        profile_digest: Hash,
        due_members: Vec<CommunityDueMemberBudgetV1>,
        maximum_required_bytes: u64,
    ) -> Result<Self> {
        let members = due_members.len() as u64;
        Self::new(CommunityBudgetQuoteInputV1 {
            timeline,
            generation,
            profile_digest,
            prior_shared_counts: CommunitySharedCountsV1::default(),
            due_members,
            maximum_required_nodes: 2 * members,
            maximum_required_edges: 2 * members,
            maximum_required_bytes,
        })
    }

    /// Require each worst-case maximum to fit its shared per-record limit,
    /// `[nodes, edges, bytes]` (owner decision on #560, 2026-11-19).
    ///
    /// # Errors
    /// Returns `BoundsExceeded` when any maximum exceeds its limit.
    pub fn require_within(&self, limits: [u64; 3]) -> Result<()> {
        let input = self.as_input();
        let maxima = [
            input.maximum_required_nodes,
            input.maximum_required_edges,
            input.maximum_required_bytes,
        ];
        if maxima
            .iter()
            .zip(limits)
            .any(|(maximum, limit)| *maximum > limit)
        {
            Err(Error::BoundsExceeded)
        } else {
            Ok(())
        }
    }

    /// Borrow the exact fields without checking any recorded set.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityBudgetQuoteInputV1 {
        &self.0
    }

    /// Encode the complete preferred CBQ1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_COMMUNITY_BUDGET_QUOTE_BYTES_V1));
        record_prefix(&mut out, 10, *b"CBQ1");
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_hash(&mut out, input.profile_digest);
        out.push(0x84);
        for value in input.prior_shared_counts.values() {
            encode_head(&mut out, 0, value);
        }
        encode_head(&mut out, 4, input.due_members.len() as u64);
        for row in &input.due_members {
            out.push(0x82);
            encode_hash(&mut out, row.member_binding_digest);
            encode_hash(&mut out, row.negotiated_tuple_digest);
        }
        encode_head(&mut out, 0, input.maximum_required_nodes);
        encode_head(&mut out, 0, input.maximum_required_edges);
        encode_head(&mut out, 0, input.maximum_required_bytes);
        out
    }

    /// `H(CBQ1)`, the CPV1 `budget_identity`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CBQ1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CBQ1.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_COMMUNITY_BUDGET_QUOTE_BYTES_V1, 10, *b"CBQ1").and_then(
            |mut cursor| {
                read_body(&mut cursor)
                    .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
            },
        )
    }
}

pub(super) fn read_counts(cursor: &mut CborCursor<'_>) -> Result<CommunitySharedCountsV1> {
    cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
        read_uints(cursor).map(|[nodes, edges, declared_inputs, encoded_record_bytes]| {
            CommunitySharedCountsV1 {
                nodes,
                edges,
                declared_inputs,
                encoded_record_bytes,
            }
        })
    })
}

fn read_due(cursor: &mut CborCursor<'_>) -> Result<CommunityDueMemberBudgetV1> {
    cursor.fixed(&[0x82]).map_err(Error::from).and_then(|()| {
        read_hashes(cursor).map(|[member_binding_digest, negotiated_tuple_digest]| {
            CommunityDueMemberBudgetV1 {
                member_binding_digest,
                negotiated_tuple_digest,
            }
        })
    })
}

fn read_body(cursor: &mut CborCursor<'_>) -> Result<CommunityBudgetQuoteInputV1> {
    read_coordinates(cursor).and_then(|(timeline, generation)| {
        read_hash(cursor).and_then(|profile_digest| {
            read_counts(cursor).and_then(|prior_shared_counts| {
                read_vec(cursor, MAX_COMMUNITY_MEMBERS_V1, read_due).and_then(|due_members| {
                    read_uints(cursor).map(|[nodes, edges, bytes]| CommunityBudgetQuoteInputV1 {
                        timeline,
                        generation,
                        profile_digest,
                        prior_shared_counts,
                        due_members,
                        maximum_required_nodes: nodes,
                        maximum_required_edges: edges,
                        maximum_required_bytes: bytes,
                    })
                })
            })
        })
    })
}

/// `N` consecutive preferred unsigned integers.
fn read_uints<const N: usize>(cursor: &mut CborCursor<'_>) -> Result<[u64; N]> {
    let mut values = [0; N];
    values
        .iter_mut()
        .try_for_each(|slot| read_head(cursor, 0).map(|value| *slot = value))
        .map(|()| values)
}
