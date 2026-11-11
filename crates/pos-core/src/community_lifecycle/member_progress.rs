//! Complete CMS1 metadata; a decoded progress record cannot restore live cells.

use super::{
    bounded_bytes, bounded_text, canonical_end, fixed_bytes, read_hash, read_hashes, read_head,
    record_cursor, record_prefix, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, DependencyNodeCoordinateV1, Hash, Seq,
    TimelineId, MAX_DEPENDENCY_OWNER_ID_BYTES_V1,
};
use zeroize::Zeroizing;

/// The accepted community profile's carried-Event bound, distinct from legacy R3.
pub const MAX_COMMUNITY_CARRIED_EVENTS_V1: usize = 3836;
const MAX_RECORD: usize = 1_048_576;
// Six IDP1 coordinate fields: array, Tick, three u32 fields, bounded owner,
// and a fixed hash. The text header needs at most two bytes for 128 bytes.
const MAX_NODE_BYTES: usize = 1 + 9 + 3 * 5 + 2 + MAX_DEPENDENCY_OWNER_ID_BYTES_V1 + 34;

/// Untrusted existing six-field IDP1 coordinate, borrowing the original owner.
///
/// The actual owner resolves its committed row, schema, class and complete
/// provenance. These fields alone establish none of those facts.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityFactualNodeReferenceV1<'a> {
    /// Existing factual Tick, never fabricated for a State-only pass.
    pub tick: u64,
    /// Original schedule position.
    pub scheduler_position: u32,
    /// Existing IDP1 owner text, at most 128 UTF-8 bytes.
    pub owner_id: &'a str,
    /// Original output ordinal.
    pub output_ordinal: u32,
    /// Original nonzero schema; its actual role requires owner verification.
    pub schema_id: u32,
    /// Exact original nonzero artifact identity.
    pub artifact_digest: Hash,
}

impl<'a> CommunityFactualNodeReferenceV1<'a> {
    /// Borrow a validated existing coordinate without cloning its owner text.
    #[must_use]
    pub const fn from_coordinate(node: &'a DependencyNodeCoordinateV1) -> Self {
        Self {
            tick: node.tick(),
            scheduler_position: node.scheduler_position(),
            owner_id: node.owner_id(),
            output_ordinal: node.output_ordinal(),
            schema_id: node.schema_id(),
            artifact_digest: node.artifact_digest(),
        }
    }
}

/// Exact progress reference tags; no tag confers source or restoration authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityProgressReferenceV1<'a> {
    /// `[0]`: claimed absence; the actual owner must independently establish it.
    None,
    /// `[1,digest]`: original pending content, not a newly produced factual Tick.
    Pending(Hash),
    /// `[2,bytes]`: the existing preferred six-field IDP1 node encoding.
    Factual(CommunityFactualNodeReferenceV1<'a>),
}

/// One original Event identity; its actual type/scope is resolved by its owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityCarriedEventV1 {
    /// Actual source Timeline, including an owning Fork prefix when applicable.
    pub timeline: TimelineId,
    /// Positive original logical Event sequence.
    pub seq: Seq,
    /// Nonzero original payload identity.
    pub payload_hash: Hash,
}

/// Original carried rows, without a second owned Event/metadata allocation.
#[derive(Clone, Copy)]
pub struct CommunityCarriedEventsV1<'a>(CarriedRows<'a>);

#[derive(Clone, Copy)]
enum CarriedRows<'a> {
    Typed(&'a [CommunityCarriedEventV1]),
    Canonical { bytes: &'a [u8], count: usize },
}

impl<'a> CommunityCarriedEventsV1<'a> {
    /// Borrow untrusted rows; the complete record validates order and bounds.
    #[must_use]
    pub const fn from_events(events: &'a [CommunityCarriedEventV1]) -> Self {
        Self(CarriedRows::Typed(events))
    }

    /// Exact row count, without constructing a collection.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            CarriedRows::Typed(rows) => rows.len(),
            CarriedRows::Canonical { count, .. } => count,
        }
    }

    /// Whether the original carried set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate the original typed or preferred encoded rows without cloning.
    pub fn iter(&self) -> CommunityCarriedEventsIterV1<'a> {
        let state = match self.0 {
            CarriedRows::Typed(rows) => CarriedIteration::Typed(rows.iter()),
            CarriedRows::Canonical { bytes, count } => CarriedIteration::Canonical {
                cursor: CborCursor::new(bytes),
                remaining: count,
            },
        };
        CommunityCarriedEventsIterV1(state)
    }

    /// Exact decoded row range for the protected owner's copy accounting.
    #[must_use]
    pub const fn as_canonical_rows(&self) -> Option<&'a [u8]> {
        match self.0 {
            CarriedRows::Typed(_) => None,
            CarriedRows::Canonical { bytes, .. } => Some(bytes),
        }
    }
}

impl<'a> IntoIterator for &CommunityCarriedEventsV1<'a> {
    type Item = Result<CommunityCarriedEventV1>;
    type IntoIter = CommunityCarriedEventsIterV1<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl PartialEq for CommunityCarriedEventsV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityCarriedEventsV1<'_> {}

/// Bounded fallible iterator, sharing the same field reader as initial decoding.
#[must_use]
pub struct CommunityCarriedEventsIterV1<'a>(CarriedIteration<'a>);

enum CarriedIteration<'a> {
    Typed(std::slice::Iter<'a, CommunityCarriedEventV1>),
    Canonical {
        cursor: CborCursor<'a>,
        remaining: usize,
    },
}

impl Iterator for CommunityCarriedEventsIterV1<'_> {
    type Item = Result<CommunityCarriedEventV1>;
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            CarriedIteration::Typed(rows) => rows.next().copied().map(Ok),
            CarriedIteration::Canonical { cursor, remaining } => {
                if *remaining == 0 {
                    None
                } else {
                    *remaining -= 1;
                    Some(read_event(cursor))
                }
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = match &self.0 {
            CarriedIteration::Typed(rows) => rows.len(),
            CarriedIteration::Canonical { remaining, .. } => *remaining,
        };
        (count, Some(count))
    }
}
impl ExactSizeIterator for CommunityCarriedEventsIterV1<'_> {}

/// Exact complete CMS1 fields; there is no independently mutable availability.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityMemberProgressInputV1<'a> {
    /// Immutable member binding identity.
    pub member_binding_digest: Hash,
    /// Complete selected producing State revision identity.
    pub state_revision_digest: Hash,
    /// Last committed step's Simulation Time; zero differs from no prior step.
    pub last_step_simulation_time: Option<u64>,
    /// Committed forwarding cursor, not a factual Tick or pass ordinal.
    pub forwarded_cursor: Seq,
    /// Strictly ordered unique `(Timeline,seq)` references.
    pub carried_events: CommunityCarriedEventsV1<'a>,
    /// Exact prior/pending step-chain reference.
    pub step_chain: CommunityProgressReferenceV1<'a>,
    /// Exact consumed-history reference.
    pub history_input: CommunityProgressReferenceV1<'a>,
}

/// Nine-field CMS1 data; it cannot read private State or adopt registry progress.
///
/// CMS1 may contain personal metadata. Its normative H(CMS1) identity must be
/// computed inside the qualified owner's audited hashing/copy boundary, not
/// through this portable codec. A zeroizing hasher alone does not cover hidden
/// plaintext copies inside the hash implementation.
///
/// ```compile_fail,E0599
/// use pos_core::community_lifecycle::CommunityMemberProgressV1;
/// fn unqualified_identity(record: &CommunityMemberProgressV1<'_>) {
///     let _ = record.digest();
/// }
/// ```
pub struct CommunityMemberProgressV1<'a>(CommunityMemberProgressInputV1<'a>);

impl<'a> CommunityMemberProgressV1<'a> {
    /// Validate local fields without trusting source classification or a cache.
    ///
    /// # Errors
    /// Rejects zero identities, invalid reference/coordinate fields, unordered
    /// or repeated Event identities and an oversized carried set. Actual source
    /// equality, committed selection and current authority remain owner checks.
    pub fn new(input: CommunityMemberProgressInputV1<'a>) -> Result<Self> {
        if [input.member_binding_digest, input.state_revision_digest].contains(&Hash::zero()) {
            return Err(Error::InvalidBinding);
        }
        validate_events(input.carried_events)
            .and_then(|()| validate_reference(input.step_chain))
            .and_then(|()| validate_reference(input.history_input))
            .map(|()| Self(input))
    }

    /// Borrow all committed-field claims, not permission to restore them.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityMemberProgressInputV1<'a> {
        &self.0
    }

    /// Encode the record in zeroizing storage, requesting its exact byte length.
    ///
    /// Compute the complete size before allocation to avoid payload-bearing
    /// growth. The owner still accounts for the actual returned capacity,
    /// including any allocator overprovisioning.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(encoded_bytes(input)));
        record_prefix(&mut out, 9, *b"CMS1");
        encode_hash(&mut out, input.member_binding_digest);
        encode_hash(&mut out, input.state_revision_digest);
        match input.last_step_simulation_time {
            Some(time) => encode_head(&mut out, 0, time),
            None => out.push(0xf6),
        }
        encode_head(&mut out, 0, input.forwarded_cursor.as_u64());
        encode_events(&mut out, input.carried_events);
        encode_reference(&mut out, input.step_chain);
        encode_reference(&mut out, input.history_input);
        out
    }

    /// Read a whole preferred CMS1, borrowing Event rows and factual owner text.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/oversized/unsupported records
    /// and invalid local fields. No class, original outcome or authority follows
    /// from decoding a factual coordinate or matching its schema number.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, MAX_RECORD, 9, *b"CMS1").and_then(|mut cursor| {
            read_progress(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

fn validate_events(events: CommunityCarriedEventsV1<'_>) -> Result<()> {
    if events.len() > MAX_COMMUNITY_CARRIED_EVENTS_V1 {
        return Err(Error::BoundsExceeded);
    }
    let mut previous = None;
    events.iter().try_for_each(|row| {
        row.and_then(|event| {
            let key = (event.timeline, event.seq);
            if event.timeline.inner().to_bytes() == [0; 16]
                || event.seq.as_u64() == 0
                || event.payload_hash == Hash::zero()
                || previous.is_some_and(|prior| prior >= key)
            {
                return Err(Error::InvalidBinding);
            }
            previous = Some(key);
            Ok(())
        })
    })
}

fn validate_reference(reference: CommunityProgressReferenceV1<'_>) -> Result<()> {
    let valid = match reference {
        CommunityProgressReferenceV1::None => true,
        CommunityProgressReferenceV1::Pending(hash) => hash != Hash::zero(),
        CommunityProgressReferenceV1::Factual(node) => {
            !node.owner_id.is_empty()
                && node.owner_id.len() <= MAX_DEPENDENCY_OWNER_ID_BYTES_V1
                && node.schema_id != 0
                && node.artifact_digest != Hash::zero()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidBinding)
    }
}

fn encode_events(out: &mut Vec<u8>, events: CommunityCarriedEventsV1<'_>) {
    encode_head(out, 4, events.len() as u64);
    match events.0 {
        CarriedRows::Canonical { bytes, .. } => out.extend_from_slice(bytes),
        CarriedRows::Typed(rows) => {
            for event in rows {
                out.push(0x83);
                encode_bytes(out, &event.timeline.inner().to_bytes(), 2);
                encode_head(out, 0, event.seq.as_u64());
                encode_hash(out, event.payload_hash);
            }
        }
    }
}

const fn uint_bytes(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=4_294_967_295 => 5,
        _ => 9,
    }
}

fn encoded_bytes(input: &CommunityMemberProgressInputV1<'_>) -> usize {
    let rows = match input.carried_events.0 {
        CarriedRows::Typed(events) => events
            .iter()
            .map(|event| 1 + 17 + uint_bytes(event.seq.as_u64()) + 34)
            .sum(),
        CarriedRows::Canonical { bytes, .. } => bytes.len(),
    };
    7 + 2 * 34
        + input.last_step_simulation_time.map_or(1, uint_bytes)
        + uint_bytes(input.forwarded_cursor.as_u64())
        + uint_bytes(input.carried_events.len() as u64)
        + rows
        + reference_bytes(input.step_chain)
        + reference_bytes(input.history_input)
}

fn reference_bytes(reference: CommunityProgressReferenceV1<'_>) -> usize {
    match reference {
        CommunityProgressReferenceV1::None => 2,
        CommunityProgressReferenceV1::Pending(_) => 2 + 34,
        CommunityProgressReferenceV1::Factual(node) => {
            let length = node_bytes(node);
            2 + uint_bytes(length as u64) + length
        }
    }
}

fn node_bytes(node: CommunityFactualNodeReferenceV1<'_>) -> usize {
    1 + uint_bytes(node.tick)
        + uint_bytes(u64::from(node.scheduler_position))
        + uint_bytes(node.owner_id.len() as u64)
        + node.owner_id.len()
        + uint_bytes(u64::from(node.output_ordinal))
        + uint_bytes(u64::from(node.schema_id))
        + 34
}

fn encode_reference(out: &mut Vec<u8>, reference: CommunityProgressReferenceV1<'_>) {
    match reference {
        CommunityProgressReferenceV1::None => out.extend_from_slice(&[0x81, 0]),
        CommunityProgressReferenceV1::Pending(hash) => {
            out.extend_from_slice(&[0x82, 1]);
            encode_hash(out, hash);
        }
        CommunityProgressReferenceV1::Factual(node) => {
            let length = node_bytes(node);
            out.extend_from_slice(&[0x82, 2]);
            encode_head(out, 2, length as u64);
            // Write directly behind the bstr head: no temporary node/owner copy.
            out.push(0x86);
            encode_head(out, 0, node.tick);
            encode_head(out, 0, u64::from(node.scheduler_position));
            encode_bytes(out, node.owner_id.as_bytes(), 3);
            encode_head(out, 0, u64::from(node.output_ordinal));
            encode_head(out, 0, u64::from(node.schema_id));
            encode_hash(out, node.artifact_digest);
        }
    }
}

fn read_event(cursor: &mut CborCursor<'_>) -> Result<CommunityCarriedEventV1> {
    cursor.fixed(&[0x83]).map_err(Error::from).and_then(|()| {
        fixed_bytes(cursor).and_then(|timeline| {
            read_head(cursor, 0).and_then(|seq| {
                read_hash(cursor).map(|payload_hash| CommunityCarriedEventV1 {
                    timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline)),
                    seq: Seq::from_u64(seq),
                    payload_hash,
                })
            })
        })
    })
}

fn read_events<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityCarriedEventsV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        if count > MAX_COMMUNITY_CARRIED_EVENTS_V1 as u64 {
            return Err(Error::BoundsExceeded);
        }
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        let start = cursor.position();
        let mut original = cursor.clone();
        (0..count)
            .try_for_each(|_| read_event(cursor).map(drop))
            .and_then(|()| {
                original
                    .take(cursor.position() - start)
                    .map_err(Error::from)
                    .map(|bytes| CommunityCarriedEventsV1(CarriedRows::Canonical { bytes, count }))
            })
    })
}

fn read_u32(cursor: &mut CborCursor<'_>) -> Result<u32> {
    read_head(cursor, 0).and_then(|value| u32::try_from(value).map_err(|_| Error::BoundsExceeded))
}

fn read_node(bytes: &[u8]) -> Result<CommunityFactualNodeReferenceV1<'_>> {
    let mut cursor = CborCursor::new(bytes);
    cursor
        .fixed(&[0x86])
        .map_err(Error::from)
        .and_then(|()| {
            read_head(&mut cursor, 0)
                .and_then(|tick| read_u32(&mut cursor).map(|position| (tick, position)))
        })
        .and_then(|(tick, scheduler_position)| {
            bounded_text(&mut cursor, MAX_DEPENDENCY_OWNER_ID_BYTES_V1).and_then(|owner_id| {
                read_u32(&mut cursor)
                    .and_then(|output_ordinal| {
                        read_u32(&mut cursor).map(|schema| (output_ordinal, schema))
                    })
                    .and_then(|(output_ordinal, schema_id)| {
                        read_hash(&mut cursor).map(|artifact_digest| {
                            CommunityFactualNodeReferenceV1 {
                                tick,
                                scheduler_position,
                                owner_id,
                                output_ordinal,
                                schema_id,
                                artifact_digest,
                            }
                        })
                    })
            })
        })
        .and_then(|node| canonical_end(&cursor).map(|()| node))
}

fn read_reference<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityProgressReferenceV1<'a>> {
    read_head(cursor, 4).and_then(|fields| {
        read_head(cursor, 0).and_then(|tag| match (fields, tag) {
            (1, 0) => Ok(CommunityProgressReferenceV1::None),
            (2, 1) => read_hash(cursor).map(CommunityProgressReferenceV1::Pending),
            (2, 2) => bounded_bytes(cursor, MAX_NODE_BYTES)
                .and_then(read_node)
                .map(CommunityProgressReferenceV1::Factual),
            _ => Err(Error::InvalidEncoding),
        })
    })
}

fn read_time(cursor: &mut CborCursor<'_>) -> Result<Option<u64>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        read_head(cursor, 0).map(Some)
    }
}

fn read_progress<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityMemberProgressInputV1<'a>> {
    let fields = read_hashes(cursor).and_then(|hashes| {
        read_time(cursor)
            .and_then(|time| read_head(cursor, 0).map(|position| (hashes, time, position)))
    });
    fields.and_then(
        |([member_binding_digest, state_revision_digest], last_step_simulation_time, position)| {
            read_events(cursor).and_then(|carried_events| {
                read_reference(cursor).and_then(|step_chain| {
                    read_reference(cursor).map(|history_input| CommunityMemberProgressInputV1 {
                        member_binding_digest,
                        state_revision_digest,
                        last_step_simulation_time,
                        forwarded_cursor: Seq::from_u64(position),
                        carried_events,
                        step_chain,
                        history_input,
                    })
                })
            })
        },
    )
}
