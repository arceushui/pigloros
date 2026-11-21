//! ADR-129 §4 CPD1 pass dependency manifest.
//!
//! CPD1 indexes one pass's complete required execution-root closure and its
//! optional presentation/Replay roots. It is the original pass's prepared
//! dependency inventory, not a causal source of its own nodes. Valid bytes do
//! not prove that the node list is complete or coordinate-sorted, or that the
//! counts are the exact checked sums: both adapters re-derive them.

use super::seal::{encode_list, read_bounded_list};
use super::{
    canonical_end, digest, read_hash, read_head, read_optional_hash, read_pass_key, read_vec,
    record_cursor, record_prefix, validate_horizon, CommunityDigestListV1, CommunityGraphCountsV1,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1, CommunitySharedCountsV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

/// Maximum canonical CPD1 encoding.
pub const MAX_COMMUNITY_DEPENDENCY_BUNDLE_BYTES_V1: usize = 1_048_576;
/// Maximum required native nodes one CPD1 lists.
pub const MAX_COMMUNITY_REQUIRED_NODES_V1: usize = 4096;
/// Largest valid encoding: framing 7, the at most 50-byte CPK1 in a two-byte
/// head 52, ordinal 9, three digests 102, 4,096 node rows in a three-byte head
/// 139,267, both roots 73, shared counts 37, graph counts at their profile-1
/// maxima 23 and the horizon 9.
const ENCODED_CAPACITY: usize = 139_579;

/// The factual bindings of a nonempty pass. A zero-Event pass has neither.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityFactualBindingV1 {
    /// Exact CTB1 identity.
    pub tick_bridge_digest: Hash,
    /// Exact factual declaration identity.
    pub factual_declaration_digest: Hash,
}

/// Optional `[role, root_digest]` evidence roots, at most one of each role.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct CommunityEvidenceRootsV1 {
    /// Role 1 `PresentationTrace` root.
    pub presentation_trace: Option<Hash>,
    /// Role 2 `ReplayRecording` root.
    pub replay_recording: Option<Hash>,
}

/// Untrusted CPD1 fields.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityDependencyBundleInputV1<'a> {
    /// Original reserved CPK1.
    pub pass_key: CommunityPassKeyV1,
    /// Positive allocated native producer ordinal.
    pub native_producer_ordinal: u64,
    /// Exact selected CGR1 identity.
    pub graph_root_digest: Hash,
    /// Both present for a nonempty pass, both null for a zero-Event pass.
    pub factual_binding: Option<CommunityFactualBindingV1>,
    /// At most 4,096 distinct CPN1 identities, in native coordinate order.
    pub required_node_digests: CommunityDigestListV1<'a>,
    /// Optional evidence roots.
    pub optional_evidence_roots: CommunityEvidenceRootsV1,
    /// `[nodes, edges, declared_inputs, encoded_record_bytes]`.
    pub shared_counts: CommunitySharedCountsV1,
    /// `[registrations, edges, keys, maximum_depth, registration_bytes,
    /// artifact_bytes]`, each within its profile-1 maximum.
    pub graph_counts: CommunityGraphCountsV1,
    /// Fixed positive horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact twelve-field CPD1.
pub struct CommunityDependencyBundleV1<'a>(CommunityDependencyBundleInputV1<'a>);

impl<'a> CommunityDependencyBundleV1<'a> {
    /// Validate identities, the node-list bound and the graph-count maxima.
    ///
    /// The required list is the execution-root closure, which contains at
    /// least the nonempty CGR1 roots. Native coordinate order and the
    /// exactness of `shared_counts` and `graph_counts` as checked sums are
    /// re-derived by both adapters (ADR-129 §4), not checked here.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero ordinal, a zero or repeated
    /// identity, and `BoundsExceeded` for no or more than 4,096 nodes, a graph
    /// count over its maximum or an invalid horizon.
    pub fn new(input: CommunityDependencyBundleInputV1<'a>) -> Result<Self> {
        if !(1..=MAX_COMMUNITY_REQUIRED_NODES_V1).contains(&input.required_node_digests.len()) {
            return Err(Error::BoundsExceeded);
        }
        let mut identities = vec![input.graph_root_digest];
        identities.extend(input.factual_binding.into_iter().flat_map(|binding| {
            [
                binding.tick_bridge_digest,
                binding.factual_declaration_digest,
            ]
        }));
        identities.extend(input.optional_evidence_roots.presentation_trace);
        identities.extend(input.optional_evidence_roots.replay_recording);
        let mut nodes: Vec<Hash> = input.required_node_digests.iter().collect();
        nodes.sort_unstable();
        if input.native_producer_ordinal == 0
            || identities.contains(&Hash::zero())
            || nodes.contains(&Hash::zero())
            || nodes.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(Error::InvalidBinding);
        }
        input
            .graph_counts
            .within_maxima()
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any node or root.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityDependencyBundleInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CPD1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(ENCODED_CAPACITY));
        record_prefix(&mut out, 12, *b"CPD1");
        let pass_key = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &pass_key, 2);
        encode_head(&mut out, 0, input.native_producer_ordinal);
        encode_hash(&mut out, input.graph_root_digest);
        match input.factual_binding {
            Some(binding) => {
                encode_hash(&mut out, binding.tick_bridge_digest);
                encode_hash(&mut out, binding.factual_declaration_digest);
            }
            None => out.extend_from_slice(&[0xf6, 0xf6]),
        }
        encode_list(&mut out, input.required_node_digests);
        let roots = [
            (1, input.optional_evidence_roots.presentation_trace),
            (2, input.optional_evidence_roots.replay_recording),
        ];
        encode_head(
            &mut out,
            4,
            roots.iter().flat_map(|(_, root)| root).count() as u64,
        );
        for (role, root) in roots {
            if let Some(root) = root {
                out.push(0x82);
                encode_head(&mut out, 0, role);
                encode_hash(&mut out, root);
            }
        }
        out.push(0x84);
        for value in input.shared_counts.values() {
            encode_head(&mut out, 0, value);
        }
        out.push(0x86);
        for value in input.graph_counts.values() {
            encode_head(&mut out, 0, value);
        }
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CPD1.v1\0" || CPD1)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CPD1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CPD1, borrowing its node list.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records, a half-null factual binding, unknown, repeated or unsorted
    /// root roles and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(
            bytes,
            MAX_COMMUNITY_DEPENDENCY_BUNDLE_BYTES_V1,
            12,
            *b"CPD1",
        )
        .and_then(|mut cursor| {
            read_bundle(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

fn read_bundle<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityDependencyBundleInputV1<'a>> {
    read_pass_key(cursor).and_then(|pass_key| {
        read_head(cursor, 0).and_then(|native_producer_ordinal| {
            read_hash(cursor).and_then(|graph_root_digest| {
                read_factual_binding(cursor).and_then(|factual_binding| {
                    read_bounded_list(cursor, MAX_COMMUNITY_REQUIRED_NODES_V1).and_then(
                        |required_node_digests| {
                            read_roots(cursor).and_then(|optional_evidence_roots| {
                                super::budget_quote::read_counts(cursor).and_then(|shared_counts| {
                                    CommunityGraphCountsV1::read(cursor).and_then(|graph_counts| {
                                        read_head(cursor, 0).map(|evidence_not_after_micros| {
                                            CommunityDependencyBundleInputV1 {
                                                pass_key,
                                                native_producer_ordinal,
                                                graph_root_digest,
                                                factual_binding,
                                                required_node_digests,
                                                optional_evidence_roots,
                                                shared_counts,
                                                graph_counts,
                                                evidence_not_after_micros,
                                            }
                                        })
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

fn read_factual_binding(cursor: &mut CborCursor<'_>) -> Result<Option<CommunityFactualBindingV1>> {
    read_optional_hash(cursor).and_then(|tick_bridge| {
        read_optional_hash(cursor).and_then(|declaration| match (tick_bridge, declaration) {
            (Some(tick_bridge_digest), Some(factual_declaration_digest)) => {
                Ok(Some(CommunityFactualBindingV1 {
                    tick_bridge_digest,
                    factual_declaration_digest,
                }))
            }
            (None, None) => Ok(None),
            _ => Err(Error::InvalidBinding),
        })
    })
}

fn read_roots(cursor: &mut CborCursor<'_>) -> Result<CommunityEvidenceRootsV1> {
    read_vec(cursor, 2, |cursor| {
        cursor
            .fixed(&[0x82])
            .map_err(Error::from)
            .and_then(|()| read_head(cursor, 0))
            .and_then(|role| read_hash(cursor).map(|root| (role, root)))
    })
    .and_then(|rows| {
        let mut roots = [None; 2];
        rows.into_iter()
            .try_fold(0, |previous, (role, root)| {
                if role <= previous || role > 2 {
                    Err(Error::InvalidEncoding)
                } else {
                    roots[usize::from(role == 2)] = Some(root);
                    Ok(role)
                }
            })
            .map(|_| CommunityEvidenceRootsV1 {
                presentation_trace: roots[0],
                replay_recording: roots[1],
            })
    })
}
