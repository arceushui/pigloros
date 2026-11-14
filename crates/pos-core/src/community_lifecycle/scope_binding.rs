//! ADR-129 §3 CSB1 scope binding.
//!
//! CSB1 binds one operation's actual delivered inputs to the complete scope
//! set derived from their native owners. Each coverage row names a typed
//! input reference by `H("TypedInputRef", canonical_ref)` and the scope set of
//! that input by `H("ScopeSet", rows)`; the complete typed reference stays in
//! CIR1/CPN1/CIB1. Valid bytes do not prove that any input exists, that its
//! owner derived these scopes, or that the union equals `scope_members`: the
//! concrete extractor performs those checks.

use super::envelope::{encode_operation, operation_len, read_operation, validate_operation};
use super::metadata_scope::{
    encode_members, members_len, read_members, validate_members, MAX_COMMUNITY_SCOPE_MEMBERS_V1,
    MAX_SCOPE_ENCODING,
};
use super::{
    bounded_text, canonical_end, digest, encode_coordinates, fixed_bytes, head_len,
    read_coordinates, read_hash, read_head, record_cursor, record_prefix, validate_coordinates,
    validate_horizon, CommunityArtifactOperationV1, CommunityLifecycleErrorV1 as Error,
    CommunityScopeMembersV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, TimelineId};
use zeroize::Zeroizing;

/// Maximum coverage rows: one per expanded actual input.
pub const MAX_COMMUNITY_COVERAGE_ROWS_V1: usize = 4096;
const MAX_BINDING: usize = 1_048_576;
/// Exact fixed `scope_rule`.
const SCOPE_RULE: &str = "pos.community.actual-input-scope";
/// `["pos.community.actual-input-scope", 1]`: array, text head and text, version.
const SCOPE_RULE_BYTES: usize = 1 + 2 + SCOPE_RULE.len() + 1;
/// Decoder bound on a foreign rule's text; longer text is `BoundsExceeded`.
const MAX_RULE_TEXT: usize = 128;
const COVERAGE_ROW_BYTES: usize = 1 + 2 * 34;
const _: () = assert!(
    256 + MAX_COMMUNITY_COVERAGE_ROWS_V1 * COVERAGE_ROW_BYTES + MAX_SCOPE_ENCODING < MAX_BINDING
);

/// One coverage row: a typed input reference and its complete scope set.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityScopeCoverageRowV1 {
    /// `H("TypedInputRef", canonical_typed_input_ref)`.
    pub typed_input_ref_digest: Hash,
    /// `H("ScopeSet", preferred array of that input's scope rows)`.
    pub scope_set_digest: Hash,
}

/// Borrowed coverage rows; the binding checks their order and bound.
#[derive(Clone, Copy)]
pub struct CommunityScopeCoverageRowsV1<'a>(CoverageRows<'a>);

#[derive(Clone, Copy)]
enum CoverageRows<'a> {
    Typed(&'a [CommunityScopeCoverageRowV1]),
    Canonical { bytes: &'a [u8], count: usize },
}

impl<'a> CommunityScopeCoverageRowsV1<'a> {
    /// Borrow caller rows; the owning record validates them.
    #[must_use]
    pub const fn from_rows(rows: &'a [CommunityScopeCoverageRowV1]) -> Self {
        Self(CoverageRows::Typed(rows))
    }

    /// Number of rows.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            CoverageRows::Typed(rows) => rows.len(),
            CoverageRows::Canonical { count, .. } => count,
        }
    }

    /// Whether no rows were supplied.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate rows; decoded rows are re-read from their validated bytes.
    pub fn iter(&self) -> impl Iterator<Item = Result<CommunityScopeCoverageRowV1>> + '_ {
        let rows = self.0;
        let mut cursor = match rows {
            CoverageRows::Typed(_) => CborCursor::new(&[]),
            CoverageRows::Canonical { bytes, .. } => CborCursor::new(bytes),
        };
        (0..self.len()).map(move |index| match rows {
            CoverageRows::Typed(typed) => Ok(typed[index]),
            CoverageRows::Canonical { .. } => read_row(&mut cursor),
        })
    }

    fn validate(self) -> Result<()> {
        if self.len() > MAX_COMMUNITY_COVERAGE_ROWS_V1 {
            return Err(Error::BoundsExceeded);
        }
        let mut previous = None;
        self.iter().try_for_each(|row| {
            row.and_then(|row| {
                if row.typed_input_ref_digest == Hash::zero()
                    || row.scope_set_digest == Hash::zero()
                    || previous.is_some_and(|prior| prior >= row.typed_input_ref_digest)
                {
                    Err(Error::InvalidBinding)
                } else {
                    previous = Some(row.typed_input_ref_digest);
                    Ok(())
                }
            })
        })
    }

    fn encode(self, out: &mut Vec<u8>) {
        encode_head(out, 4, self.len() as u64);
        match self.0 {
            CoverageRows::Typed(rows) => rows.iter().for_each(|row| {
                out.push(0x82);
                encode_hash(out, row.typed_input_ref_digest);
                encode_hash(out, row.scope_set_digest);
            }),
            CoverageRows::Canonical { bytes, .. } => out.extend_from_slice(bytes),
        }
    }

    fn read(cursor: &mut CborCursor<'a>) -> Result<Self> {
        read_head(cursor, 4).and_then(|count| {
            if count > MAX_COMMUNITY_COVERAGE_ROWS_V1 as u64 {
                return Err(Error::BoundsExceeded);
            }
            let count = usize::try_from(count).unwrap_or(usize::MAX);
            let start = cursor.position();
            let mut original = cursor.clone();
            (0..count)
                .try_for_each(|_| read_row(cursor).map(drop))
                .and_then(|()| {
                    original
                        .take(cursor.position() - start)
                        .map_err(Error::from)
                        .map(|bytes| Self(CoverageRows::Canonical { bytes, count }))
                })
        })
    }
}

impl PartialEq for CommunityScopeCoverageRowsV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityScopeCoverageRowsV1<'_> {}

fn read_row(cursor: &mut CborCursor<'_>) -> Result<CommunityScopeCoverageRowV1> {
    cursor.fixed(&[0x82]).map_err(Error::from).and_then(|()| {
        read_hash(cursor).and_then(|typed_input_ref_digest| {
            read_hash(cursor).map(|scope_set_digest| CommunityScopeCoverageRowV1 {
                typed_input_ref_digest,
                scope_set_digest,
            })
        })
    })
}

/// Untrusted CSB1 fields; `scope_rule` is fixed and not a field here.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityScopeBindingInputV1<'a> {
    /// Nonzero protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// Execution Timeline.
    pub timeline: TimelineId,
    /// Execution generation.
    pub generation: [u8; 16],
    /// ADR-128 operation kind and identity (Pass/CPK1, Initialization, Control).
    pub operation: CommunityArtifactOperationV1,
    /// Prepared CIN1/input-set digest, or the CGI1/control request digest.
    pub input_identity: Hash,
    /// At most 4096 rows, strictly ascending by typed-ref digest.
    pub coverage_rows: CommunityScopeCoverageRowsV1<'a>,
    /// Complete scope set, at most 2048 rows in strict CSM1 row order.
    pub scope_members: CommunityScopeMembersV1<'a>,
    /// Pinned installed source-policy digest.
    pub policy_revision: Hash,
    /// Original positive evidence horizon.
    pub evidence_not_after_micros: u64,
}

/// Exact thirteen-field CSB1.
pub struct CommunityScopeBindingV1<'a>(CommunityScopeBindingInputV1<'a>);

impl<'a> CommunityScopeBindingV1<'a> {
    /// Validate local identities, row order and bounds.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for zero or unordered identities and a pass
    /// key for another Timeline/generation, and `BoundsExceeded` for more than
    /// 4096 coverage rows, more than 2048 scope members or an invalid horizon.
    pub fn new(input: CommunityScopeBindingInputV1<'a>) -> Result<Self> {
        if input.scope_members.len() > MAX_COMMUNITY_SCOPE_MEMBERS_V1 {
            return Err(Error::BoundsExceeded);
        }
        if input.store_incarnation == [0; 16]
            || input.input_identity == Hash::zero()
            || input.policy_revision == Hash::zero()
        {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_operation(input.operation, input.timeline, input.generation))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .and_then(|()| input.coverage_rows.validate())
            .and_then(|()| validate_members(input.scope_members))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without resolving any input or scope.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityScopeBindingInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CSB1 into zeroizing storage sized
    /// exactly, so no reallocation leaves an unwiped copy.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(encoded_len(input)));
        record_prefix(&mut out, 13, *b"CSB1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_operation(&mut out, input.operation);
        encode_hash(&mut out, input.input_identity);
        input.coverage_rows.encode(&mut out);
        encode_members(&mut out, input.scope_members);
        encode_scope_rule(&mut out);
        encode_hash(&mut out, input.policy_revision);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// ADR-128 `ScopeCover` commitment, not the generic CSB1 record domain.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.ScopeCover.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode one complete preferred CSB1, borrowing its variable rows.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records, another scope rule and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_BINDING, 13, *b"CSB1").and_then(|mut cursor| {
            read_body(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

/// Exact CSB1 length: framing and version (7), incarnation (17), T and G
/// (34), the operation, the input and policy hashes (2 x 34), the two row
/// arrays, the rule and the horizon.
fn encoded_len(input: &CommunityScopeBindingInputV1<'_>) -> usize {
    7 + 17
        + 34
        + operation_len(input.operation)
        + 2 * 34
        + head_len(input.coverage_rows.len() as u64)
        + input.coverage_rows.len() * COVERAGE_ROW_BYTES
        + members_len(input.scope_members)
        + SCOPE_RULE_BYTES
        + head_len(input.evidence_not_after_micros)
}

fn read_body<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityScopeBindingInputV1<'a>> {
    fixed_bytes(cursor).and_then(|store_incarnation| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_operation(cursor).and_then(|operation| {
                read_hash(cursor).and_then(|input_identity| {
                    CommunityScopeCoverageRowsV1::read(cursor).and_then(|coverage_rows| {
                        read_members(cursor).and_then(|scope_members| {
                            read_scope_rule(cursor)
                                .and_then(|()| read_hash(cursor))
                                .and_then(|policy_revision| {
                                    read_head(cursor, 0).map(|evidence_not_after_micros| {
                                        CommunityScopeBindingInputV1 {
                                            store_incarnation,
                                            timeline,
                                            generation,
                                            operation,
                                            input_identity,
                                            coverage_rows,
                                            scope_members,
                                            policy_revision,
                                            evidence_not_after_micros,
                                        }
                                    })
                                })
                        })
                    })
                })
            })
        })
    })
}

/// `["pos.community.actual-input-scope", 1]`.
fn encode_scope_rule(out: &mut Vec<u8>) {
    out.push(0x82);
    encode_bytes(out, SCOPE_RULE.as_bytes(), 3);
    encode_head(out, 0, 1);
}

/// Parse the rule structurally: a non-preferred or truncated encoding is
/// `InvalidEncoding`; a well-formed rule that is not this one is
/// `InvalidBinding`.
fn read_scope_rule(cursor: &mut CborCursor<'_>) -> Result<()> {
    read_head(cursor, 4).and_then(|fields| {
        if fields != 2 {
            return Err(Error::InvalidBinding);
        }
        bounded_text(cursor, MAX_RULE_TEXT).and_then(|rule| {
            read_head(cursor, 0).and_then(|version| {
                if rule == SCOPE_RULE && version == 1 {
                    Ok(())
                } else {
                    Err(Error::InvalidBinding)
                }
            })
        })
    })
}
