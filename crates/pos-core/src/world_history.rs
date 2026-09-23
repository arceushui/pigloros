//! Immutable structural WEP1 source-event pages and WHB1 history branches.
//!
//! These records describe bounded source history. They do not verify stored
//! Events, source chains, Fork lineage, native dependencies, or Replay use.

use crate::{
    CanonicalBytes, CorrelationId, EntityId, EventId, Hash, SchemaVersion, Signature, TimelineId,
};
use ulid::Ulid;

/// Maximum canonical WEP1 record size.
pub const MAX_WORLD_EVENT_PAGE_BYTES_V1: usize = 65_536;
/// Maximum source-event rows in one WEP1 page.
pub const MAX_WORLD_EVENT_PAGE_ROWS_V1: usize = 64;
/// Maximum UTF-8 byte length of one source-event type.
pub const MAX_WORLD_EVENT_TYPE_BYTES_V1: usize = 128;
/// Maximum canonical WHB1 record size.
pub const MAX_WORLD_HISTORY_BRANCH_BYTES_V1: usize = 65_536;
/// Maximum child references in one WHB1 branch.
pub const MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1: usize = 256;
/// Maximum WHB1 tree height.
pub const MAX_WORLD_HISTORY_HEIGHT_V1: u8 = 8;

const WEP1_MAGIC: &[u8; 4] = b"WEP1";
const WHB1_MAGIC: &[u8; 4] = b"WHB1";
const VERSION: u64 = 1;
const EVENT_PAGE_DOMAIN: &[u8] = b"pigloros.world-evidence.event-page.v1\0";
const HISTORY_BRANCH_DOMAIN: &[u8] = b"pigloros.world-evidence.history-branch.v1\0";

/// Closed structural WEP1/WHB1 codec errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldHistoryErrorV1 {
    /// A record is malformed or has an unexpected CBOR type or field width.
    #[error("invalid World history encoding")]
    InvalidEncoding,
    /// A record does not use the expected WEP1 or WHB1 magic.
    #[error("wrong World history record magic")]
    WrongMagic,
    /// A record uses an unsupported record version.
    #[error("unsupported World history record version")]
    WrongVersion,
    /// A source row uses an unsupported schema marker.
    #[error("unsupported source schema version")]
    UnsupportedSchemaVersion,
    /// A field, count, or complete record exceeds its accepted bound.
    #[error("World history field is out of bounds")]
    FieldOutOfBounds,
    /// A field ordering or whole-input representation is not canonical.
    #[error("World history encoding is not canonical")]
    NonCanonicalEncoding,
    /// A logical range is empty, discontinuous, inconsistent, or overflows.
    #[error("World history range is invalid")]
    InvalidRange,
    /// A resolved child does not match its WHB1 reference or query context.
    #[error("World history child does not match its parent reference")]
    InvalidChildReference,
    /// One WEP1 page repeats a source Event identity.
    #[error("World history page repeats a source Event")]
    DuplicateSourceEvent,
    /// A required content-address field is zero.
    #[error("World history content address is zero")]
    ZeroContentAddress,
}

/// Untrusted source-event fields for one immutable WEP1 row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldEventRowInputV1 {
    /// Position in the queried Timeline's stitched logical history.
    pub logical_seq: u64,
    /// Timeline that owns the source Event segment, including inherited Fork rows.
    pub source_timeline_id: TimelineId,
    /// Segment-local sequence at the source Timeline.
    pub source_segment_seq: u64,
    /// Source Event identity.
    pub event_id: EventId,
    /// Event entity identity.
    pub entity_id: EntityId,
    /// Exact source event type.
    pub event_type: String,
    /// The only supported V1 schema marker is the unsigned integer 1.
    pub schema_version: u64,
    /// Source wall-clock time in microseconds.
    pub wall_time_micros: u64,
    /// Source causation Event, when present.
    pub causation_id: Option<EventId>,
    /// Source correlation identity, when present.
    pub correlation_id: Option<CorrelationId>,
    /// Native hash of the source Event payload.
    pub payload_hash: Hash,
    /// Source payload byte length.
    pub payload_byte_length: u32,
    /// Source-chain predecessor hash. The pinned Hasher owns its semantics.
    pub previous_source_chain_hash: Hash,
    /// Source-chain result hash. The pinned Hasher owns its semantics.
    pub resulting_source_chain_hash: Hash,
    /// Exact source signature bytes, when present.
    pub signature: Option<Signature>,
    /// WAL1 address for the signature identity evidence, when present.
    pub signature_identity_leaf_hash: Option<Hash>,
    /// WAL1 address for the source payload artifact.
    pub payload_leaf_hash: Hash,
    /// WDB1 root for dependencies applicable to this source Event.
    pub applicable_dependency_root_hash: Hash,
}

/// Immutable structurally validated WEP1 source-event row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldEventRowV1(WorldEventRowInputV1);

impl WorldEventRowV1 {
    /// Validate structural bounds and content-address fields for one row.
    ///
    /// # Errors
    /// Rejects zero/out-of-range fields and unsupported schema versions. It
    /// intentionally does not validate source Event or signature authority.
    pub fn new(input: WorldEventRowInputV1) -> Result<Self, WorldHistoryErrorV1> {
        validate_event_row(&input).map(|()| Self(input))
    }

    /// Borrow the immutable source-row fields.
    #[must_use]
    pub const fn as_input(&self) -> &WorldEventRowInputV1 {
        &self.0
    }
}

/// Immutable WEP1 page covering a contiguous non-empty logical source range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldEventPageV1 {
    timeline_id: TimelineId,
    first_logical_seq: u64,
    last_logical_seq: u64,
    rows: Vec<WorldEventRowV1>,
}

impl WorldEventPageV1 {
    /// Construct one page from already validated rows in logical order.
    ///
    /// # Errors
    /// Rejects empty/oversized pages, gaps, out-of-order sequences, or
    /// repeated source Event identities.
    pub fn new(
        timeline_id: TimelineId,
        rows: Vec<WorldEventRowV1>,
    ) -> Result<Self, WorldHistoryErrorV1> {
        validate_event_page_rows(&rows).map(|(first_logical_seq, last_logical_seq)| Self {
            timeline_id,
            first_logical_seq,
            last_logical_seq,
            rows,
        })
    }

    /// Decode and validate the complete preferred WEP1 representation.
    ///
    /// # Errors
    /// Rejects oversized, malformed, noncanonical, or structurally invalid bytes.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldHistoryErrorV1> {
        if bytes.len() > MAX_WORLD_EVENT_PAGE_BYTES_V1 {
            return Err(WorldHistoryErrorV1::FieldOutOfBounds);
        }
        let mut parser = Parser::new(bytes.as_slice());
        parser.event_page().and_then(|page| {
            ensure_finished(&parser).and_then(|()| {
                if page.encode().as_slice() == bytes.as_slice() {
                    Ok(page)
                } else {
                    Err(WorldHistoryErrorV1::NonCanonicalEncoding)
                }
            })
        })
    }

    /// Encode the exact preferred definite WEP1 representation.
    #[must_use]
    pub fn encode(&self) -> CanonicalBytes {
        let mut output = Vec::new();
        encode_array(&mut output, 6);
        encode_bytes(&mut output, WEP1_MAGIC);
        encode_unsigned(&mut output, VERSION);
        encode_id(&mut output, self.timeline_id.inner());
        encode_unsigned(&mut output, self.first_logical_seq);
        encode_unsigned(&mut output, self.last_logical_seq);
        encode_array(&mut output, self.rows.len());
        for row in &self.rows {
            encode_event_row(&mut output, row.as_input());
        }
        CanonicalBytes::from_vec(output)
    }

    /// Return the domain-separated WEP1 content address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(EVENT_PAGE_DOMAIN, self.encode().as_slice())
    }

    /// Return the queried Timeline identity.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    /// Return the first logical sequence covered by this page.
    #[must_use]
    pub const fn first_logical_seq(&self) -> u64 {
        self.first_logical_seq
    }

    /// Return the last logical sequence covered by this page.
    #[must_use]
    pub const fn last_logical_seq(&self) -> u64 {
        self.last_logical_seq
    }

    /// Return the contiguous source rows in logical order.
    #[must_use]
    pub fn rows(&self) -> &[WorldEventRowV1] {
        &self.rows
    }
}

/// Immutable WHB1 child range reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldHistoryChildV1 {
    first_logical_seq: u64,
    last_logical_seq: u64,
    event_count: u64,
    node_hash: Hash,
}

impl WorldHistoryChildV1 {
    /// Validate one positive inclusive range and its content-addressed child.
    ///
    /// # Errors
    /// Rejects an empty or inconsistent range and a zero child address.
    pub fn new(
        first_logical_seq: u64,
        last_logical_seq: u64,
        event_count: u64,
        node_hash: Hash,
    ) -> Result<Self, WorldHistoryErrorV1> {
        validate_range(first_logical_seq, last_logical_seq, event_count).and_then(|()| {
            validate_content_address(node_hash).map(|()| Self {
                first_logical_seq,
                last_logical_seq,
                event_count,
                node_hash,
            })
        })
    }

    /// Return the first logical sequence in the child range.
    #[must_use]
    pub const fn first_logical_seq(self) -> u64 {
        self.first_logical_seq
    }

    /// Return the last logical sequence in the child range.
    #[must_use]
    pub const fn last_logical_seq(self) -> u64 {
        self.last_logical_seq
    }

    /// Return the exact number of Events in the child range.
    #[must_use]
    pub const fn event_count(self) -> u64 {
        self.event_count
    }

    /// Return the child node content address.
    #[must_use]
    pub const fn node_hash(self) -> Hash {
        self.node_hash
    }
}

/// Untrusted fields used to construct one immutable WHB1 branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldHistoryBranchInputV1 {
    /// Queried Timeline identity for every descendant in this closure.
    pub timeline_id: TimelineId,
    /// Branch height: one for WEP1 leaves, increasing toward the root.
    pub height: u8,
    /// First logical sequence covered by this branch.
    pub first_logical_seq: u64,
    /// Last logical sequence covered by this branch.
    pub last_logical_seq: u64,
    /// Total Event count covered by this branch.
    pub event_count: u64,
    /// Ordered, contiguous child ranges.
    pub children: Vec<WorldHistoryChildV1>,
}

/// Immutable structurally validated WHB1 history branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldHistoryBranchV1(WorldHistoryBranchInputV1);

impl WorldHistoryBranchV1 {
    /// Construct one branch after checking its full range partition.
    ///
    /// # Errors
    /// Rejects invalid height, empty/oversized branches, gaps, overlaps,
    /// duplicate child addresses, or inconsistent counts.
    pub fn new(input: WorldHistoryBranchInputV1) -> Result<Self, WorldHistoryErrorV1> {
        validate_history_branch(&input).map(|()| Self(input))
    }

    /// Decode and validate the complete preferred WHB1 representation.
    ///
    /// # Errors
    /// Rejects oversized, malformed, noncanonical, or structurally invalid bytes.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldHistoryErrorV1> {
        if bytes.len() > MAX_WORLD_HISTORY_BRANCH_BYTES_V1 {
            return Err(WorldHistoryErrorV1::FieldOutOfBounds);
        }
        let mut parser = Parser::new(bytes.as_slice());
        parser.history_branch().and_then(|branch| {
            ensure_finished(&parser).and_then(|()| {
                if branch.encode().as_slice() == bytes.as_slice() {
                    Ok(branch)
                } else {
                    Err(WorldHistoryErrorV1::NonCanonicalEncoding)
                }
            })
        })
    }

    /// Encode the exact preferred definite WHB1 representation.
    #[must_use]
    pub fn encode(&self) -> CanonicalBytes {
        let input = &self.0;
        let mut output = Vec::new();
        encode_array(&mut output, 8);
        encode_bytes(&mut output, WHB1_MAGIC);
        encode_unsigned(&mut output, VERSION);
        encode_id(&mut output, input.timeline_id.inner());
        encode_unsigned(&mut output, u64::from(input.height));
        encode_unsigned(&mut output, input.first_logical_seq);
        encode_unsigned(&mut output, input.last_logical_seq);
        encode_unsigned(&mut output, input.event_count);
        encode_array(&mut output, input.children.len());
        for child in &input.children {
            encode_array(&mut output, 4);
            encode_unsigned(&mut output, child.first_logical_seq);
            encode_unsigned(&mut output, child.last_logical_seq);
            encode_unsigned(&mut output, child.event_count);
            encode_hash(&mut output, child.node_hash);
        }
        CanonicalBytes::from_vec(output)
    }

    /// Return the domain-separated WHB1 content address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(HISTORY_BRANCH_DOMAIN, self.encode().as_slice())
    }

    /// Borrow the immutable validated branch fields.
    #[must_use]
    pub const fn as_input(&self) -> &WorldHistoryBranchInputV1 {
        &self.0
    }

    /// Validate already-resolved child records against their WHB1 summaries.
    ///
    /// The caller resolves the records from its owner snapshot and separately
    /// verifies source Event occurrences. This method checks exact record
    /// identity, query Timeline, child level, range, and content address; the
    /// validated inclusive ranges bind the child counts.
    ///
    /// # Errors
    /// Rejects a different query Timeline, a missing/extra child, or any child
    /// record that does not match its encoded WHB1 summary.
    pub fn validate_resolved_children(
        &self,
        queried_timeline_id: TimelineId,
        records: &[WorldHistoryChildRecordRefV1<'_>],
    ) -> Result<(), WorldHistoryErrorV1> {
        if self.0.timeline_id != queried_timeline_id || records.len() != self.0.children.len() {
            return Err(WorldHistoryErrorV1::InvalidChildReference);
        }
        for (child, record) in self.0.children.iter().zip(records) {
            let matches = match (self.0.height, record) {
                (1, WorldHistoryChildRecordRefV1::EventPage(page)) => {
                    page.timeline_id == queried_timeline_id
                        && page.first_logical_seq == child.first_logical_seq
                        && page.last_logical_seq == child.last_logical_seq
                        && page.digest() == child.node_hash
                }
                (height, WorldHistoryChildRecordRefV1::HistoryBranch(branch)) if height > 1 => {
                    branch.0.timeline_id == queried_timeline_id
                        && branch.0.height.checked_add(1) == Some(height)
                        && branch.0.first_logical_seq == child.first_logical_seq
                        && branch.0.last_logical_seq == child.last_logical_seq
                        && branch.digest() == child.node_hash
                }
                _ => false,
            };
            if !matches {
                return Err(WorldHistoryErrorV1::InvalidChildReference);
            }
        }
        Ok(())
    }
}

/// A decoded record supplied by the storage owner for one WHB1 child reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorldHistoryChildRecordRefV1<'a> {
    /// A WEP1 page, valid only as a height-1 branch child.
    EventPage(&'a WorldEventPageV1),
    /// A WHB1 branch, valid only below a parent at the next height.
    HistoryBranch(&'a WorldHistoryBranchV1),
}

fn validate_event_row(input: &WorldEventRowInputV1) -> Result<(), WorldHistoryErrorV1> {
    if input.logical_seq == 0
        || input.source_segment_seq == 0
        || input.event_type.is_empty()
        || input.event_type.len() > MAX_WORLD_EVENT_TYPE_BYTES_V1
    {
        return Err(WorldHistoryErrorV1::FieldOutOfBounds);
    }
    if input.schema_version != u64::from(SchemaVersion::V1.as_u32()) {
        return Err(WorldHistoryErrorV1::UnsupportedSchemaVersion);
    }
    validate_content_address(input.payload_hash)
        .and_then(|()| validate_content_address(input.payload_leaf_hash))
        .and_then(|()| validate_content_address(input.applicable_dependency_root_hash))
        .and_then(|()| {
            input
                .signature_identity_leaf_hash
                .map_or(Ok(()), validate_content_address)
        })
}

fn validate_event_page_rows(rows: &[WorldEventRowV1]) -> Result<(u64, u64), WorldHistoryErrorV1> {
    if rows.is_empty() || rows.len() > MAX_WORLD_EVENT_PAGE_ROWS_V1 {
        return Err(WorldHistoryErrorV1::FieldOutOfBounds);
    }
    let mut identities = Vec::with_capacity(rows.len());
    let mut first_logical_seq = 0;
    let mut last_logical_seq = 0;
    for (index, row) in rows.iter().enumerate() {
        let input = row.as_input();
        if index == 0 {
            first_logical_seq = input.logical_seq;
        }
        last_logical_seq = input.logical_seq;
        if index > 0 {
            let previous = rows[index - 1].as_input();
            if previous.logical_seq.checked_add(1) != Some(input.logical_seq)
                || (previous.source_timeline_id == input.source_timeline_id
                    && previous.source_segment_seq.checked_add(1) != Some(input.source_segment_seq))
            {
                return Err(WorldHistoryErrorV1::InvalidRange);
            }
        }
        let identity = (
            input.source_timeline_id,
            input.source_segment_seq,
            input.event_id,
        );
        if identities.contains(&identity) {
            return Err(WorldHistoryErrorV1::DuplicateSourceEvent);
        }
        identities.push(identity);
    }
    Ok((first_logical_seq, last_logical_seq))
}

fn validate_history_branch(input: &WorldHistoryBranchInputV1) -> Result<(), WorldHistoryErrorV1> {
    if input.height == 0 || input.height > MAX_WORLD_HISTORY_HEIGHT_V1 {
        return Err(WorldHistoryErrorV1::FieldOutOfBounds);
    }
    if input.children.is_empty() || input.children.len() > MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1 {
        return Err(WorldHistoryErrorV1::FieldOutOfBounds);
    }
    let maximum_event_count = max_history_node_event_count(input.height);
    if input.event_count > maximum_event_count {
        return Err(WorldHistoryErrorV1::FieldOutOfBounds);
    }
    let child_maximum_event_count = if input.height == 1 {
        u64::try_from(MAX_WORLD_EVENT_PAGE_ROWS_V1).unwrap_or(u64::MAX)
    } else {
        max_history_node_event_count(input.height - 1)
    };
    validate_range(
        input.first_logical_seq,
        input.last_logical_seq,
        input.event_count,
    )
    .and_then(|()| {
        let mut expected_first = input.first_logical_seq;
        let mut child_hashes = Vec::with_capacity(input.children.len());
        let mut child_validation = Ok(());
        for (index, child) in input.children.iter().enumerate() {
            child_validation = child_validation.and_then(|()| {
                if child.first_logical_seq != expected_first {
                    return Err(WorldHistoryErrorV1::InvalidRange);
                }
                validate_range(
                    child.first_logical_seq,
                    child.last_logical_seq,
                    child.event_count,
                )
                .and_then(|()| {
                    if child.event_count > child_maximum_event_count {
                        return Err(WorldHistoryErrorV1::FieldOutOfBounds);
                    }
                    if index + 1 < input.children.len()
                        && child.event_count != child_maximum_event_count
                    {
                        return Err(WorldHistoryErrorV1::InvalidRange);
                    }
                    if child_hashes.contains(&child.node_hash) {
                        return Err(WorldHistoryErrorV1::InvalidRange);
                    }
                    child_hashes.push(child.node_hash);
                    if index + 1 < input.children.len() {
                        match child.last_logical_seq.checked_add(1) {
                            Some(next) => expected_first = next,
                            None => return Err(WorldHistoryErrorV1::InvalidRange),
                        }
                    }
                    Ok(())
                })
            });
        }
        child_validation.and_then(|()| {
            if input.children.last().map(|child| child.last_logical_seq)
                != Some(input.last_logical_seq)
            {
                Err(WorldHistoryErrorV1::InvalidRange)
            } else {
                Ok(())
            }
        })
    })
}

fn max_history_node_event_count(height: u8) -> u64 {
    let mut maximum = u64::try_from(MAX_WORLD_EVENT_PAGE_ROWS_V1).unwrap_or(u64::MAX);
    for _ in 0..height {
        maximum = match maximum
            .checked_mul(u64::try_from(MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1).unwrap_or(u64::MAX))
        {
            Some(value) => value,
            None => return u64::MAX,
        };
    }
    maximum
}

const fn validate_range(
    first_logical_seq: u64,
    last_logical_seq: u64,
    event_count: u64,
) -> Result<(), WorldHistoryErrorV1> {
    if first_logical_seq == 0 || last_logical_seq < first_logical_seq {
        return Err(WorldHistoryErrorV1::InvalidRange);
    }
    // The preceding checks prove `1 <= first <= last <= u64::MAX`, so this
    // inclusive distance fits in `u64` without a fallible arithmetic path.
    let inclusive_count = last_logical_seq - first_logical_seq + 1;
    if event_count == 0 || event_count != inclusive_count {
        return Err(WorldHistoryErrorV1::InvalidRange);
    }
    Ok(())
}

fn validate_content_address(hash: Hash) -> Result<(), WorldHistoryErrorV1> {
    if hash == Hash::zero() {
        Err(WorldHistoryErrorV1::ZeroContentAddress)
    } else {
        Ok(())
    }
}

const fn ensure_finished(parser: &Parser<'_>) -> Result<(), WorldHistoryErrorV1> {
    if parser.finished() {
        Ok(())
    } else {
        Err(WorldHistoryErrorV1::InvalidEncoding)
    }
}

fn encode_event_row(output: &mut Vec<u8>, input: &WorldEventRowInputV1) {
    encode_array(output, 18);
    encode_unsigned(output, input.logical_seq);
    encode_id(output, input.source_timeline_id.inner());
    encode_unsigned(output, input.source_segment_seq);
    encode_id(output, input.event_id.inner());
    encode_id(output, input.entity_id.inner());
    encode_text(output, &input.event_type);
    encode_unsigned(output, input.schema_version);
    encode_unsigned(output, input.wall_time_micros);
    encode_optional_id(output, input.causation_id);
    encode_optional_correlation(output, input.correlation_id);
    encode_hash(output, input.payload_hash);
    encode_unsigned(output, u64::from(input.payload_byte_length));
    encode_hash(output, input.previous_source_chain_hash);
    encode_hash(output, input.resulting_source_chain_hash);
    encode_optional_signature(output, input.signature);
    encode_optional_hash(output, input.signature_identity_leaf_hash);
    encode_hash(output, input.payload_leaf_hash);
    encode_hash(output, input.applicable_dependency_root_hash);
}

fn encode_optional_id(output: &mut Vec<u8>, id: Option<EventId>) {
    if let Some(id) = id {
        encode_id(output, id.inner());
    } else {
        output.push(0xf6);
    }
}

fn encode_optional_correlation(output: &mut Vec<u8>, id: Option<CorrelationId>) {
    if let Some(id) = id {
        encode_id(output, id.inner());
    } else {
        output.push(0xf6);
    }
}

fn encode_optional_signature(output: &mut Vec<u8>, signature: Option<Signature>) {
    if let Some(signature) = signature {
        encode_bytes(output, signature.as_bytes());
    } else {
        output.push(0xf6);
    }
}

fn encode_optional_hash(output: &mut Vec<u8>, hash: Option<Hash>) {
    if let Some(hash) = hash {
        encode_hash(output, hash);
    } else {
        output.push(0xf6);
    }
}

fn encode_id(output: &mut Vec<u8>, id: Ulid) {
    encode_bytes(output, &u128::from(id).to_be_bytes());
}

fn encode_hash(output: &mut Vec<u8>, hash: Hash) {
    encode_bytes(output, hash.as_bytes());
}

fn encode_array(output: &mut Vec<u8>, length: usize) {
    encode_head(output, 4, length as u64);
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    encode_head(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

fn encode_text(output: &mut Vec<u8>, value: &str) {
    encode_head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

fn encode_unsigned(output: &mut Vec<u8>, value: u64) {
    encode_head(output, 0, value);
}

fn encode_head(output: &mut Vec<u8>, major_type: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let prefix = major_type << 5;
    match value {
        0..=23 => output.push(prefix | bytes[7]),
        24..=0xff => {
            output.extend_from_slice(&[prefix | 0x18, bytes[7]]);
        }
        0x100..=0xffff => {
            output.push(prefix | 0x19);
            output.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 0x1a);
            output.extend_from_slice(&bytes[4..]);
        }
        _ => {
            output.push(prefix | 0x1b);
            output.extend_from_slice(&bytes);
        }
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn timeline_id_from_bytes(bytes: [u8; 16]) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(u128::from_be_bytes(bytes)))
}

fn event_id_from_bytes(bytes: [u8; 16]) -> EventId {
    EventId::from_ulid(Ulid::from(u128::from_be_bytes(bytes)))
}

fn entity_id_from_bytes(bytes: [u8; 16]) -> EntityId {
    EntityId::from_ulid(Ulid::from(u128::from_be_bytes(bytes)))
}

fn correlation_id_from_bytes(bytes: [u8; 16]) -> CorrelationId {
    CorrelationId::from_ulid(Ulid::from(u128::from_be_bytes(bytes)))
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn event_page(&mut self) -> Result<WorldEventPageV1, WorldHistoryErrorV1> {
        let mut timeline_id = timeline_id_from_bytes([0; 16]);
        let mut first = 0;
        let mut last = 0;
        let mut rows = Vec::new();
        self.array_exact(6)
            .and_then(|()| self.magic(*WEP1_MAGIC))
            .and_then(|()| self.version())
            .and_then(|()| {
                self.fixed::<16>(2, 16)
                    .map(|bytes| timeline_id = timeline_id_from_bytes(bytes))
            })
            .and_then(|()| self.unsigned().map(|value| first = value))
            .and_then(|()| self.unsigned().map(|value| last = value))
            .and_then(|()| self.event_rows().map(|value| rows = value))
            .and_then(|()| WorldEventPageV1::new(timeline_id, rows))
            .and_then(|page| {
                if page.first_logical_seq == first && page.last_logical_seq == last {
                    Ok(page)
                } else {
                    Err(WorldHistoryErrorV1::InvalidRange)
                }
            })
    }

    fn history_branch(&mut self) -> Result<WorldHistoryBranchV1, WorldHistoryErrorV1> {
        let mut timeline_id = timeline_id_from_bytes([0; 16]);
        let mut height = 0;
        let mut first_logical_seq = 0;
        let mut last_logical_seq = 0;
        let mut event_count = 0;
        let mut children = Vec::new();
        self.array_exact(8)
            .and_then(|()| self.magic(*WHB1_MAGIC))
            .and_then(|()| self.version())
            .and_then(|()| {
                self.fixed::<16>(2, 16)
                    .map(|bytes| timeline_id = timeline_id_from_bytes(bytes))
            })
            .and_then(|()| {
                self.unsigned().and_then(|value| {
                    u8::try_from(value)
                        .map(|value| height = value)
                        .map_err(|_| WorldHistoryErrorV1::FieldOutOfBounds)
                })
            })
            .and_then(|()| self.unsigned().map(|value| first_logical_seq = value))
            .and_then(|()| self.unsigned().map(|value| last_logical_seq = value))
            .and_then(|()| self.unsigned().map(|value| event_count = value))
            .and_then(|()| self.history_children().map(|value| children = value))
            .and_then(|()| {
                WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
                    timeline_id,
                    height,
                    first_logical_seq,
                    last_logical_seq,
                    event_count,
                    children,
                })
            })
    }

    fn event_rows(&mut self) -> Result<Vec<WorldEventRowV1>, WorldHistoryErrorV1> {
        self.array_bounded(1, MAX_WORLD_EVENT_PAGE_ROWS_V1)
            .and_then(|count| {
                let mut rows = Vec::with_capacity(count);
                let mut result = Ok(());
                for _ in 0..count {
                    result = result.and_then(|()| self.event_row().map(|row| rows.push(row)));
                }
                result.map(|()| rows)
            })
    }

    fn event_row(&mut self) -> Result<WorldEventRowV1, WorldHistoryErrorV1> {
        // Success through the entire chain assigns every field before the
        // validated row is constructed; initial values cannot escape.
        let mut input = WorldEventRowInputV1 {
            logical_seq: 0,
            source_timeline_id: timeline_id_from_bytes([0; 16]),
            source_segment_seq: 0,
            event_id: event_id_from_bytes([0; 16]),
            entity_id: entity_id_from_bytes([0; 16]),
            event_type: String::new(),
            schema_version: 0,
            wall_time_micros: 0,
            causation_id: None,
            correlation_id: None,
            payload_hash: Hash::zero(),
            payload_byte_length: 0,
            previous_source_chain_hash: Hash::zero(),
            resulting_source_chain_hash: Hash::zero(),
            signature: None,
            signature_identity_leaf_hash: None,
            payload_leaf_hash: Hash::zero(),
            applicable_dependency_root_hash: Hash::zero(),
        };
        self.array_exact(18)
            .and_then(|()| self.unsigned().map(|value| input.logical_seq = value))
            .and_then(|()| {
                self.fixed::<16>(2, 16).map(|bytes| {
                    input.source_timeline_id = timeline_id_from_bytes(bytes);
                })
            })
            .and_then(|()| {
                self.unsigned()
                    .map(|value| input.source_segment_seq = value)
            })
            .and_then(|()| {
                self.fixed::<16>(2, 16)
                    .map(|bytes| input.event_id = event_id_from_bytes(bytes))
            })
            .and_then(|()| {
                self.fixed::<16>(2, 16)
                    .map(|bytes| input.entity_id = entity_id_from_bytes(bytes))
            })
            .and_then(|()| {
                self.text_bounded(MAX_WORLD_EVENT_TYPE_BYTES_V1)
                    .map(|value| input.event_type = value)
            })
            .and_then(|()| self.unsigned().map(|value| input.schema_version = value))
            .and_then(|()| self.unsigned().map(|value| input.wall_time_micros = value))
            .and_then(|()| {
                self.optional_fixed::<16>(2, 16)
                    .map(|value| input.causation_id = value.map(event_id_from_bytes))
            })
            .and_then(|()| {
                self.optional_fixed::<16>(2, 16)
                    .map(|value| input.correlation_id = value.map(correlation_id_from_bytes))
            })
            .and_then(|()| {
                self.fixed::<32>(2, 32)
                    .map(|bytes| input.payload_hash = Hash::from_bytes(bytes))
            })
            .and_then(|()| {
                self.unsigned().and_then(|value| {
                    u32::try_from(value)
                        .map(|value| input.payload_byte_length = value)
                        .map_err(|_| WorldHistoryErrorV1::FieldOutOfBounds)
                })
            })
            .and_then(|()| {
                self.fixed::<32>(2, 32).map(|bytes| {
                    input.previous_source_chain_hash = Hash::from_bytes(bytes);
                })
            })
            .and_then(|()| {
                self.fixed::<32>(2, 32).map(|bytes| {
                    input.resulting_source_chain_hash = Hash::from_bytes(bytes);
                })
            })
            .and_then(|()| {
                self.optional_fixed::<64>(2, 64)
                    .map(|value| input.signature = value.map(Signature::from_bytes))
            })
            .and_then(|()| {
                self.optional_fixed::<32>(2, 32)
                    .map(|value| input.signature_identity_leaf_hash = value.map(Hash::from_bytes))
            })
            .and_then(|()| {
                self.fixed::<32>(2, 32)
                    .map(|bytes| input.payload_leaf_hash = Hash::from_bytes(bytes))
            })
            .and_then(|()| {
                self.fixed::<32>(2, 32).map(|bytes| {
                    input.applicable_dependency_root_hash = Hash::from_bytes(bytes);
                })
            })
            .and_then(|()| WorldEventRowV1::new(input))
    }

    fn history_children(&mut self) -> Result<Vec<WorldHistoryChildV1>, WorldHistoryErrorV1> {
        self.array_bounded(1, MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1)
            .and_then(|count| {
                let mut children = Vec::with_capacity(count);
                let mut result = Ok(());
                for _ in 0..count {
                    result = result
                        .and_then(|()| self.history_child().map(|child| children.push(child)));
                }
                result.map(|()| children)
            })
    }

    fn history_child(&mut self) -> Result<WorldHistoryChildV1, WorldHistoryErrorV1> {
        let mut first = 0;
        let mut last = 0;
        let mut count = 0;
        let mut node_hash = Hash::zero();
        self.array_exact(4)
            .and_then(|()| self.unsigned().map(|value| first = value))
            .and_then(|()| self.unsigned().map(|value| last = value))
            .and_then(|()| self.unsigned().map(|value| count = value))
            .and_then(|()| {
                self.fixed::<32>(2, 32)
                    .map(|bytes| node_hash = Hash::from_bytes(bytes))
            })
            .and_then(|()| WorldHistoryChildV1::new(first, last, count, node_hash))
    }

    fn magic(&mut self, expected: [u8; 4]) -> Result<(), WorldHistoryErrorV1> {
        self.fixed::<4>(2, expected.len()).and_then(|actual| {
            if actual == expected {
                Ok(())
            } else {
                Err(WorldHistoryErrorV1::WrongMagic)
            }
        })
    }

    fn version(&mut self) -> Result<(), WorldHistoryErrorV1> {
        self.unsigned().and_then(|version| {
            if version == VERSION {
                Ok(())
            } else {
                Err(WorldHistoryErrorV1::WrongVersion)
            }
        })
    }

    fn array_exact(&mut self, expected: usize) -> Result<(), WorldHistoryErrorV1> {
        self.header(4).and_then(|length| {
            if length == expected as u64 {
                Ok(())
            } else {
                Err(WorldHistoryErrorV1::InvalidEncoding)
            }
        })
    }

    fn array_bounded(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<usize, WorldHistoryErrorV1> {
        self.header(4).and_then(|encoded_length| {
            usize::try_from(encoded_length)
                .map_err(|_| WorldHistoryErrorV1::FieldOutOfBounds)
                .and_then(|length| {
                    if (minimum..=maximum).contains(&length) {
                        Ok(length)
                    } else {
                        Err(WorldHistoryErrorV1::FieldOutOfBounds)
                    }
                })
        })
    }

    fn unsigned(&mut self) -> Result<u64, WorldHistoryErrorV1> {
        self.header(0)
    }

    fn text_bounded(&mut self, maximum: usize) -> Result<String, WorldHistoryErrorV1> {
        self.header(3).and_then(|encoded_length| {
            usize::try_from(encoded_length)
                .map_err(|_| WorldHistoryErrorV1::FieldOutOfBounds)
                .and_then(|length| {
                    if length == 0 || length > maximum {
                        Err(WorldHistoryErrorV1::FieldOutOfBounds)
                    } else {
                        self.take(length).and_then(|bytes| {
                            std::str::from_utf8(bytes)
                                .map(str::to_owned)
                                .map_err(|_| WorldHistoryErrorV1::InvalidEncoding)
                        })
                    }
                })
        })
    }

    fn fixed<const N: usize>(
        &mut self,
        major_type: u8,
        expected_length: usize,
    ) -> Result<[u8; N], WorldHistoryErrorV1> {
        self.header(major_type).and_then(|encoded_length| {
            usize::try_from(encoded_length)
                .map_err(|_| WorldHistoryErrorV1::FieldOutOfBounds)
                .and_then(|length| {
                    if length == expected_length {
                        self.take(length).and_then(|bytes| {
                            bytes
                                .try_into()
                                .map_err(|_| WorldHistoryErrorV1::InvalidEncoding)
                        })
                    } else {
                        Err(WorldHistoryErrorV1::InvalidEncoding)
                    }
                })
        })
    }

    fn optional_fixed<const N: usize>(
        &mut self,
        major_type: u8,
        expected_length: usize,
    ) -> Result<Option<[u8; N]>, WorldHistoryErrorV1> {
        if self.bytes.get(self.position) == Some(&0xf6) {
            self.position += 1;
            Ok(None)
        } else {
            self.fixed(major_type, expected_length).map(Some)
        }
    }

    fn header(&mut self, expected_major_type: u8) -> Result<u64, WorldHistoryErrorV1> {
        self.raw::<1>().and_then(|[first]| {
            if first >> 5 == expected_major_type {
                self.additional(first & 0x1f)
            } else {
                Err(WorldHistoryErrorV1::InvalidEncoding)
            }
        })
    }

    fn additional(&mut self, additional: u8) -> Result<u64, WorldHistoryErrorV1> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => self.raw::<1>().map(|[byte]| u64::from(byte)),
            25 => self
                .raw::<2>()
                .map(|bytes| u64::from(u16::from_be_bytes(bytes))),
            26 => self
                .raw::<4>()
                .map(|bytes| u64::from(u32::from_be_bytes(bytes))),
            27 => self.raw::<8>().map(u64::from_be_bytes),
            _ => Err(WorldHistoryErrorV1::InvalidEncoding),
        }
    }

    fn raw<const N: usize>(&mut self) -> Result<[u8; N], WorldHistoryErrorV1> {
        self.take(N).and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|_| WorldHistoryErrorV1::InvalidEncoding)
        })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WorldHistoryErrorV1> {
        // All calls follow a parser bound: fixed widths are at most 64 bytes,
        // text is at most 128 bytes, and the enclosing record is capped at 64
        // KiB, so this sum cannot overflow `usize`.
        let end = self.position + length;
        match self.bytes.get(self.position..end) {
            Some(value) => {
                self.position = end;
                Ok(value)
            }
            None => Err(WorldHistoryErrorV1::InvalidEncoding),
        }
    }
}
