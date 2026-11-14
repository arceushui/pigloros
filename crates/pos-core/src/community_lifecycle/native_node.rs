//! ADR-129 §4 CPN1 native producer node and its closed node kinds.
//!
//! A node is data. It records one native producer's logical content, its
//! exact earlier inputs and independently computed scope, authorization and
//! provenance identities. The concrete native owner allocates the producer
//! ordinal, mints the node and resolves every input; decoding a node grants
//! none of that and issues no guest permit.

use super::input_reference::{
    CommunityNativeNodeReferenceV1, CommunityNativeNodeReferencesV1, CommunityTypedInputRefV1,
    CommunityTypedInputRefsV1,
};
use super::{
    bounded_text, canonical_end, digest, encode_coordinates, fixed_bytes, read_coordinates,
    read_hash, read_hashes, read_head, record_cursor, record_prefix, validate_coordinates,
    validate_horizon, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, Hash, RecordedDependencyClassV1, TimelineId,
};
use zeroize::Zeroizing;

const MAX_NODE: usize = 1_048_576;
/// Maximum direct typed references in one input index or CIB1 group.
pub const MAX_COMMUNITY_DIRECT_INPUTS_V1: usize = 256;
/// Maximum expanded inputs of one grouped input index.
pub const MAX_COMMUNITY_EXPANDED_INPUTS_V1: usize = 4096;
// 4096 expanded inputs in 256-input chunks.
const MAX_GROUPS: usize = 16;
const MAX_RULE_BYTES: usize = 64;

/// Closed native node kinds with their fixed rule and class.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityNativeNodeKindV1 {
    /// Kind 0, `pos.community.initial-state`, `EndogenousRecomputed`.
    InitialState,
    /// Kind 1, `pos.community.observation`, `EndogenousRecomputed`.
    Observation,
    /// Kind 2, `pos.community.invocation-step`, `EndogenousRecomputed`.
    InvocationStep,
    /// Kind 3, `pos.community.state-revision`, `EndogenousRecomputed`.
    StateRevision,
    /// Kind 4, `pos.community.event-output`, the admitted Event output class.
    ///
    /// The codec cannot know that class: the native owner (A3/A4) must check
    /// it against the actual admitted output policy before committing.
    EventOutput,
    /// Kind 5, `pos.community.annotation`, `PresentationOnly`.
    Annotation,
    /// Kind 6, `pos.community.measurement`, `PresentationOnly`.
    Measurement,
    /// Kind 7, `pos.community.admitted-policy`, `FixedPolicy`.
    AdmittedPolicy,
    /// Kind 8, `pos.community.host-progress`, `EndogenousRecomputed`.
    HostProgress,
    /// Kind 9, `pos.community.input-index`, the consumer's class.
    ///
    /// The codec cannot know that class: the native owner (A3/A4) must check
    /// it equals the consuming node's class before committing.
    InputIndex,
}

impl CommunityNativeNodeKindV1 {
    const ALL: [Self; 10] = [
        Self::InitialState,
        Self::Observation,
        Self::InvocationStep,
        Self::StateRevision,
        Self::EventOutput,
        Self::Annotation,
        Self::Measurement,
        Self::AdmittedPolicy,
        Self::HostProgress,
        Self::InputIndex,
    ];

    /// Exact wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Exact closed classification rule identifier; every version is 1.
    #[must_use]
    pub const fn rule_id(self) -> &'static str {
        match self {
            Self::InitialState => "pos.community.initial-state",
            Self::Observation => "pos.community.observation",
            Self::InvocationStep => "pos.community.invocation-step",
            Self::StateRevision => "pos.community.state-revision",
            Self::EventOutput => "pos.community.event-output",
            Self::Annotation => "pos.community.annotation",
            Self::Measurement => "pos.community.measurement",
            Self::AdmittedPolicy => "pos.community.admitted-policy",
            Self::HostProgress => "pos.community.host-progress",
            Self::InputIndex => "pos.community.input-index",
        }
    }

    /// Fixed class, or `None` where the admitted Event output class or the
    /// consumer's class applies and the native owner must check it.
    #[must_use]
    pub const fn fixed_class(self) -> Option<RecordedDependencyClassV1> {
        match self {
            Self::EventOutput | Self::InputIndex => None,
            Self::Annotation | Self::Measurement => {
                Some(RecordedDependencyClassV1::PresentationOnly)
            }
            Self::AdmittedPolicy => Some(RecordedDependencyClassV1::FixedPolicy),
            _ => Some(RecordedDependencyClassV1::EndogenousRecomputed),
        }
    }

    /// Content magic fixed by the ADR, if any: CPI1 for an invocation step
    /// and CIB1 for an input index. Other kinds are owner-checked.
    #[must_use]
    pub const fn fixed_content(self) -> Option<[u8; 4]> {
        match self {
            Self::InvocationStep => Some(*b"CPI1"),
            Self::InputIndex => Some(*b"CIB1"),
            _ => None,
        }
    }

    fn from_code(code: u64) -> Result<Self> {
        usize::try_from(code)
            .ok()
            .and_then(|index| Self::ALL.get(index).copied())
            .ok_or(Error::InvalidEncoding)
    }
}

/// `[record_magic4, logical_digest32]`: a logical record identity, not
/// its physical materialization.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityContentReferenceV1 {
    /// Four-byte record magic, ASCII upper-case letters and digits.
    pub record_magic: [u8; 4],
    /// Logical record digest.
    pub logical_digest: Hash,
}

impl CommunityContentReferenceV1 {
    pub(super) fn validate(self) -> Result<()> {
        if self
            .record_magic
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            && self.logical_digest != Hash::zero()
        {
            Ok(())
        } else {
            Err(Error::InvalidBinding)
        }
    }

    pub(super) fn encode(self, out: &mut Vec<u8>) {
        out.push(0x82);
        encode_bytes(out, &self.record_magic, 2);
        encode_hash(out, self.logical_digest);
    }

    pub(super) fn read(cursor: &mut CborCursor<'_>) -> Result<Self> {
        cursor.fixed(&[0x82]).map_err(Error::from).and_then(|()| {
            fixed_bytes(cursor).and_then(|record_magic| {
                read_hash(cursor).map(|logical_digest| Self {
                    record_magic,
                    logical_digest,
                })
            })
        })
    }
}

/// Exact input index: `[0]`, `[1, refs]` or `[2, group_refs, total]`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityInputIndexV1<'a> {
    /// No input.
    Empty,
    /// 1..=256 direct typed references in canonical order.
    Direct(CommunityTypedInputRefsV1<'a>),
    /// 257..=4096 expanded inputs grouped by earlier `InputIndex` nodes.
    Grouped {
        /// Exactly one group per consecutive 256-input chunk, 2..=16.
        groups: CommunityNativeNodeReferencesV1<'a>,
        /// Total expanded leaf inputs.
        total_leaf_count: u64,
    },
}

impl CommunityInputIndexV1<'_> {
    fn validate(self) -> Result<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Direct(references) => references.validate(1, MAX_COMMUNITY_DIRECT_INPUTS_V1),
            Self::Grouped {
                groups,
                total_leaf_count,
            } => {
                let leaves = usize::try_from(total_leaf_count).unwrap_or(usize::MAX);
                if leaves <= MAX_COMMUNITY_DIRECT_INPUTS_V1
                    || leaves > MAX_COMMUNITY_EXPANDED_INPUTS_V1
                {
                    Err(Error::BoundsExceeded)
                } else if groups.len() == leaves.div_ceil(MAX_COMMUNITY_DIRECT_INPUTS_V1) {
                    groups.validate(0, MAX_GROUPS)
                } else {
                    Err(Error::InvalidBinding)
                }
            }
        }
    }

    /// Every native reference of this index precedes the consumer within
    /// the same store incarnation.
    fn check_native_sources(
        self,
        store_incarnation: [u8; 16],
        producer_ordinal: u64,
        node_ordinal: u32,
    ) -> Result<()> {
        let check = |reference: CommunityNativeNodeReferenceV1| {
            if reference.store_incarnation == store_incarnation
                && reference.precedes(producer_ordinal, node_ordinal)
            {
                Ok(())
            } else {
                Err(Error::InvalidBinding)
            }
        };
        match self {
            Self::Empty => Ok(()),
            Self::Direct(references) => references.iter().try_for_each(|row| {
                row.and_then(|reference| match reference {
                    CommunityTypedInputRefV1::Native(native) => check(native),
                    _ => Ok(()),
                })
            }),
            Self::Grouped { groups, .. } => groups.iter().try_for_each(|row| row.and_then(check)),
        }
    }

    fn encode(self, out: &mut Vec<u8>) {
        match self {
            Self::Empty => out.extend_from_slice(&[0x81, 0]),
            Self::Direct(references) => {
                out.extend_from_slice(&[0x82, 1]);
                references.encode(out);
            }
            Self::Grouped {
                groups,
                total_leaf_count,
            } => {
                out.extend_from_slice(&[0x83, 2]);
                groups.encode(out);
                encode_head(out, 0, total_leaf_count);
            }
        }
    }
}

fn read_index<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityInputIndexV1<'a>> {
    read_head(cursor, 4).and_then(|fields| {
        read_head(cursor, 0).and_then(|form| match (fields, form) {
            (1, 0) => Ok(CommunityInputIndexV1::Empty),
            (2, 1) => CommunityTypedInputRefsV1::read(cursor, MAX_COMMUNITY_DIRECT_INPUTS_V1)
                .map(CommunityInputIndexV1::Direct),
            (3, 2) => {
                CommunityNativeNodeReferencesV1::read(cursor, MAX_GROUPS).and_then(|groups| {
                    read_head(cursor, 0).map(|total_leaf_count| CommunityInputIndexV1::Grouped {
                        groups,
                        total_leaf_count,
                    })
                })
            }
            _ => Err(Error::InvalidEncoding),
        })
    })
}

/// Untrusted CPN1 fields. The rule identifier and version are fixed by the
/// node kind and are not separate inputs.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityNativeNodeInputV1<'a> {
    /// Nonzero store incarnation.
    pub store_incarnation: [u8; 16],
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// Positive native producer ordinal.
    pub producer_ordinal: u64,
    /// Node ordinal within the producer.
    pub node_ordinal: u32,
    /// Closed node kind.
    pub kind: CommunityNativeNodeKindV1,
    /// Logical content identity.
    pub content: CommunityContentReferenceV1,
    /// Dependency class; fixed by most kinds.
    pub dependency_class: RecordedDependencyClassV1,
    /// Exact earlier inputs.
    pub input_index: CommunityInputIndexV1<'a>,
    /// Independently derived scope binding identity.
    pub scope_binding_digest: Hash,
    /// Independently derived authorization identity.
    pub authorization_digest: Hash,
    /// Independently derived provenance identity.
    pub provenance_digest: Hash,
    /// Fixed positive horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact sixteen-field CPN1. Valid bytes prove neither existence nor use.
pub struct CommunityNativeNodeV1<'a>(CommunityNativeNodeInputV1<'a>);

impl<'a> CommunityNativeNodeV1<'a> {
    /// Validate identities, the closed kind mapping and the input index.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero identities, a class or content magic
    /// the kind forbids, a grouped input index under an `InputIndex` node,
    /// unordered or duplicate inputs, or a native input from another store
    /// incarnation or not strictly before this node; `BoundsExceeded` for
    /// input counts or the horizon outside their bounds.
    pub fn new(input: CommunityNativeNodeInputV1<'a>) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_node(&input))
            .and_then(|()| input.content.validate())
            .and_then(|()| input.input_index.validate())
            .and_then(|()| {
                input.input_index.check_native_sources(
                    input.store_incarnation,
                    input.producer_ordinal,
                    input.node_ordinal,
                )
            })
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any input.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityNativeNodeInputV1<'a> {
        &self.0
    }

    /// The native reference naming this exact node.
    #[must_use]
    pub fn reference(&self) -> CommunityNativeNodeReferenceV1 {
        CommunityNativeNodeReferenceV1 {
            store_incarnation: self.0.store_incarnation,
            producer_ordinal: self.0.producer_ordinal,
            node_ordinal: self.0.node_ordinal,
            node_digest: self.digest(),
        }
    }

    /// Encode the complete preferred CPN1 into zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 16, *b"CPN1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_head(&mut out, 0, input.producer_ordinal);
        encode_head(&mut out, 0, u64::from(input.node_ordinal));
        encode_head(&mut out, 0, u64::from(input.kind.code()));
        input.content.encode(&mut out);
        encode_head(&mut out, 0, u64::from(input.dependency_class.code()));
        out.push(0x82);
        encode_bytes(&mut out, input.kind.rule_id().as_bytes(), 3);
        encode_head(&mut out, 0, 1);
        input.input_index.encode(&mut out);
        encode_hash(&mut out, input.scope_binding_digest);
        encode_hash(&mut out, input.authorization_digest);
        encode_hash(&mut out, input.provenance_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// `BLAKE3("PiglorOS.Community.CPN1.v1\0" || CPN1)`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CPN1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CPN1, borrowing its input rows.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records, unknown kind or class codes, a rule other than the kind's
    /// exact rule and version 1, and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_NODE, 16, *b"CPN1").and_then(|mut cursor| {
            read_node(&mut cursor)
                .and_then(Self::new)
                .and_then(|node| canonical_end(&cursor).map(|()| node))
        })
    }
}

fn validate_node(input: &CommunityNativeNodeInputV1<'_>) -> Result<()> {
    let kind = input.kind;
    if input.store_incarnation == [0; 16]
        || input.producer_ordinal == 0
        || [
            input.scope_binding_digest,
            input.authorization_digest,
            input.provenance_digest,
        ]
        .contains(&Hash::zero())
        || kind
            .fixed_class()
            .is_some_and(|class| class != input.dependency_class)
        || kind
            .fixed_content()
            .is_some_and(|magic| magic != input.content.record_magic)
        || (kind == CommunityNativeNodeKindV1::InputIndex
            && !matches!(input.input_index, CommunityInputIndexV1::Direct(_)))
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn read_class(cursor: &mut CborCursor<'_>) -> Result<RecordedDependencyClassV1> {
    read_head(cursor, 0).and_then(|code| {
        RecordedDependencyClassV1::from_code(code).map_err(|_| Error::InvalidEncoding)
    })
}

fn read_rule(cursor: &mut CborCursor<'_>, kind: CommunityNativeNodeKindV1) -> Result<()> {
    cursor.fixed(&[0x82]).map_err(Error::from).and_then(|()| {
        bounded_text(cursor, MAX_RULE_BYTES).and_then(|rule| {
            read_head(cursor, 0).and_then(|version| {
                if rule == kind.rule_id() && version == 1 {
                    Ok(())
                } else {
                    Err(Error::InvalidBinding)
                }
            })
        })
    })
}

fn read_node<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityNativeNodeInputV1<'a>> {
    let head = fixed_bytes(cursor).and_then(|store_incarnation| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_head(cursor, 0).and_then(|producer_ordinal| {
                read_head(cursor, 0)
                    .and_then(|node| u32::try_from(node).map_err(|_| Error::BoundsExceeded))
                    .map(|node_ordinal| {
                        (
                            store_incarnation,
                            timeline,
                            generation,
                            producer_ordinal,
                            node_ordinal,
                        )
                    })
            })
        })
    });
    head.and_then(
        |(store_incarnation, timeline, generation, producer_ordinal, node_ordinal)| {
            read_head(cursor, 0)
                .and_then(CommunityNativeNodeKindV1::from_code)
                .and_then(|kind| {
                    CommunityContentReferenceV1::read(cursor).and_then(|content| {
                        read_class(cursor).and_then(|dependency_class| {
                            read_rule(cursor, kind)
                                .and_then(|()| read_index(cursor))
                                .and_then(|input_index| {
                                    read_hashes(cursor).and_then(
                                        |[scope_binding_digest, authorization_digest, provenance_digest]| {
                                            read_head(cursor, 0).map(|evidence_not_after_micros| {
                                                CommunityNativeNodeInputV1 {
                                                    store_incarnation,
                                                    timeline,
                                                    generation,
                                                    producer_ordinal,
                                                    node_ordinal,
                                                    kind,
                                                    content,
                                                    dependency_class,
                                                    input_index,
                                                    scope_binding_digest,
                                                    authorization_digest,
                                                    provenance_digest,
                                                    evidence_not_after_micros,
                                                }
                                            })
                                        },
                                    )
                                })
                        })
                    })
                })
        },
    )
}
