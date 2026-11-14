//! ADR-129 §2 CGR1 selected execution graph root.
//!
//! CGR1 names every required selected member, input and provenance root of
//! one selected head. It excludes presentation, measurement and Replay
//! receipt roots, a final receipt and its own COA. Valid bytes do not prove
//! that the closure is complete, current or traversable; the native
//! extractor must resolve and charge every referenced node.

use super::input_reference::CommunityNativeNodeReferencesV1;
use super::{
    canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates, read_hashes,
    read_head, record_cursor, record_prefix, validate_coordinates, validate_horizon,
    CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

/// Maximum canonical CGR1 encoding.
pub const MAX_COMMUNITY_GRAPH_ROOT_BYTES_V1: usize = 65_536;

/// Most roots that can fit the byte bound: a native reference is at least
/// 1 + 17 + 1 + 1 + 34 = 54 bytes, and 65,536 / 54 is 1213.
const MAX_GRAPH_ROOTS: usize = 1213;

/// Profile 1 graph maxima from `graph_policy_bytes`: registrations, edges,
/// keys, depth, registration bytes and artifact bytes.
const GRAPH_MAXIMA: [u64; 6] = [4096, 8192, 4096, 4096, 67_108_864, 268_435_456];

/// `[registrations, edges, keys, maximum_depth, registration_bytes,
/// artifact_bytes]`, exact checked sums re-derived by the native owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityGraphCountsV1 {
    /// Distinct registrations.
    pub registrations: u64,
    /// Distinct edges.
    pub edges: u64,
    /// Distinct keys.
    pub keys: u64,
    /// Maximum traversal depth.
    pub maximum_depth: u64,
    /// Registration bytes.
    pub registration_bytes: u64,
    /// Exact artifact bytes.
    pub artifact_bytes: u64,
}

impl CommunityGraphCountsV1 {
    const fn values(self) -> [u64; 6] {
        [
            self.registrations,
            self.edges,
            self.keys,
            self.maximum_depth,
            self.registration_bytes,
            self.artifact_bytes,
        ]
    }

    /// Every count is within its profile-1 maximum. Each distinct root is
    /// its own registration and depth counts the root as one, so a nonempty
    /// root set needs at least one registration per root and a depth from 1
    /// up to the number of registrations.
    fn validate(self, roots: usize) -> Result<()> {
        if self
            .values()
            .iter()
            .zip(GRAPH_MAXIMA)
            .any(|(value, maximum)| *value > maximum)
        {
            Err(Error::BoundsExceeded)
        } else if self.registrations < roots as u64
            || self.maximum_depth == 0
            || self.maximum_depth > self.registrations
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }

    fn read(cursor: &mut CborCursor<'_>) -> Result<Self> {
        let mut values = [0; 6];
        cursor
            .fixed(&[0x86])
            .map_err(Error::from)
            .and_then(|()| {
                values
                    .iter_mut()
                    .try_for_each(|slot| read_head(cursor, 0).map(|value| *slot = value))
            })
            .map(|()| Self {
                registrations: values[0],
                edges: values[1],
                keys: values[2],
                maximum_depth: values[3],
                registration_bytes: values[4],
                artifact_bytes: values[5],
            })
    }
}

/// Untrusted CGR1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityGraphRootInputV1<'a> {
    /// Nonzero store incarnation shared by every root reference.
    pub store_incarnation: [u8; 16],
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// Exact CDP1 identity.
    pub profile_digest: Hash,
    /// Exact selected CSH1 identity.
    pub selected_head_digest: Hash,
    /// Nonempty root references in strictly ascending native order.
    pub roots: CommunityNativeNodeReferencesV1<'a>,
    /// Exact graph counts.
    pub graph_counts: CommunityGraphCountsV1,
    /// Fixed positive horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact ten-field CGR1.
pub struct CommunityGraphRootV1<'a>(CommunityGraphRootInputV1<'a>);

impl<'a> CommunityGraphRootV1<'a> {
    /// Validate identities, ordered same-incarnation roots, profile-1 count
    /// maxima, the horizon and the encoded bound.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero, unordered, duplicate or foreign
    /// identities and `BoundsExceeded` for no roots, a count over its
    /// maximum, an invalid horizon or an encoding over 65,536 bytes.
    pub fn new(input: CommunityGraphRootInputV1<'a>) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| {
                if input.store_incarnation == [0; 16]
                    || [input.profile_digest, input.selected_head_digest].contains(&Hash::zero())
                {
                    Err(Error::InvalidBinding)
                } else {
                    input.roots.validate(1, MAX_GRAPH_ROOTS)
                }
            })
            .and_then(|()| {
                input.roots.iter().try_for_each(|row| {
                    row.and_then(|root| {
                        if root.store_incarnation == input.store_incarnation {
                            Ok(())
                        } else {
                            Err(Error::InvalidBinding)
                        }
                    })
                })
            })
            .and_then(|()| input.graph_counts.validate(input.roots.len()))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
            .and_then(|root| {
                if root.to_canonical_cbor().len() > MAX_COMMUNITY_GRAPH_ROOT_BYTES_V1 {
                    Err(Error::BoundsExceeded)
                } else {
                    Ok(root)
                }
            })
    }

    /// Borrow exact fields without traversing the graph.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityGraphRootInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CGR1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 10, *b"CGR1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_hash(&mut out, input.profile_digest);
        encode_hash(&mut out, input.selected_head_digest);
        input.roots.encode(&mut out);
        out.push(0x86);
        for value in input.graph_counts.values() {
            encode_head(&mut out, 0, value);
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CGR1.v1\0" || CGR1)`, the CGA1 graph root.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CGR1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CGR1, borrowing its root rows.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_COMMUNITY_GRAPH_ROOT_BYTES_V1, 10, *b"CGR1").and_then(
            |mut cursor| {
                read_root(&mut cursor)
                    .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
            },
        )
    }
}

fn read_root<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityGraphRootInputV1<'a>> {
    fixed_bytes(cursor).and_then(|store_incarnation| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_hashes(cursor).and_then(|[profile_digest, selected_head_digest]| {
                CommunityNativeNodeReferencesV1::read(cursor, MAX_GRAPH_ROOTS).and_then(|roots| {
                    CommunityGraphCountsV1::read(cursor).and_then(|graph_counts| {
                        read_head(cursor, 0).map(|evidence_not_after_micros| {
                            CommunityGraphRootInputV1 {
                                store_incarnation,
                                timeline,
                                generation,
                                profile_digest,
                                selected_head_digest,
                                roots,
                                graph_counts,
                                evidence_not_after_micros,
                            }
                        })
                    })
                })
            })
        })
    })
}
