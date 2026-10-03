//! Immutable RCP1 recompute checkpoints defined by ADR-064.
//!
//! A `RecomputeCheckpointV1` binds one deterministic counterfactual suffix
//! recomputation coordinate to the exact Plugin, Projection, and state digests
//! that were committed at that coordinate. This module owns only the strict
//! codec, the domain-separated digest, and structural validation; checkpoint
//! persistence, eviction, state serialization, Tick execution, and recovery
//! belong to the core `CounterfactualCoordinator`.

use super::codec::{
    bytes_value, decode_canonical, encode_value, text_value, uint_value, CborLimits, FieldReader,
    WireError,
};
use crate::domain_digest;
use ciborium::value::Value;
use std::cmp::Ordering;

/// Magic for the immutable recompute-checkpoint record.
pub const RECOMPUTE_CHECKPOINT_MAGIC_V1: &str = "RCP1";
/// Maximum encoded size of an RCP1 recompute checkpoint.
///
/// A structurally valid RCP1 record encodes to at most about 2 MiB (three
/// lists of 4,096 entries of at most 165 bytes each plus fixed fields), so the
/// limit is enforced on untrusted input before allocation rather than after
/// encoding.
pub const MAX_RECOMPUTE_CHECKPOINT_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of entries in each ordered RCP1 digest list.
pub const MAX_CHECKPOINT_DIGEST_ENTRIES_V1: usize = 4_096;
/// Maximum encoded byte length of one RCP1 owner identifier.
pub const MAX_CHECKPOINT_OWNER_ID_BYTES_V1: usize = 128;
/// Maximum exogenous cursor position; a plan freezes at most 65,536 descriptors.
pub const MAX_EXOGENOUS_CURSOR_POSITION_V1: u64 = 65_536;

const FIELD_COUNT: usize = 12;
const DIGEST_DOMAIN: &[u8] = b"PiglorOS.RecomputeCheckpoint.v1";
const LIMITS: CborLimits = CborLimits {
    maximum_bytes: MAX_RECOMPUTE_CHECKPOINT_BYTES_V1,
    maximum_depth: 3,
    maximum_items: 4_096,
    allow_simple_values: true,
};
const ZERO_DIGEST: [u8; 32] = [0; 32];

/// Closed safe errors exposed by the RCP1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecomputeCheckpointContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic or schema version is not supported.
    UnsupportedVersion,
    /// A required value or encoded record exceeds its specified bound.
    FieldOutOfBounds,
    /// An ordered digest list is not in canonical owner-identifier order.
    NonCanonicalOrder,
    /// An ordered digest list names the same owner identifier twice.
    DuplicateIdentity,
    /// The content does not match its declared checkpoint digest.
    DigestMismatch,
}

impl std::fmt::Display for RecomputeCheckpointContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid RCP1 recompute checkpoint encoding",
            Self::UnsupportedVersion => "unsupported RCP1 recompute checkpoint version",
            Self::FieldOutOfBounds => "RCP1 recompute checkpoint field is out of bounds",
            Self::NonCanonicalOrder => "RCP1 recompute checkpoint lists are not canonical",
            Self::DuplicateIdentity => "RCP1 recompute checkpoint owner is duplicated",
            Self::DigestMismatch => "RCP1 recompute checkpoint digest does not match",
        })
    }
}

impl std::error::Error for RecomputeCheckpointContractErrorV1 {}

/// One owner-keyed digest in an ordered RCP1 digest list.
///
/// The owner identifier is canonical UTF-8 of 1 through 128 bytes; the digest
/// is a nonzero 32-byte content identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointDigestEntryV1 {
    pub owner_id: String,
    pub digest: [u8; 32],
}

/// Position in the plan's ordered frozen exogenous descriptor sequence.
///
/// `consumed_descriptors` counts the descriptors consumed through this
/// checkpoint. The last consumed descriptor digest is absent exactly when no
/// descriptor has been consumed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExogenousCursorV1 {
    pub consumed_descriptors: u64,
    pub last_descriptor_digest: Option<[u8; 32]>,
}

/// The complete immutable recompute checkpoint represented by an RCP1 record.
///
/// The exact deterministic-CBOR array has 12 fields: magic, version, plan
/// digest, tick, seq, scheduler position, Plugin state digests, Projection
/// digests, state digests, exogenous cursor, provenance root, and the
/// checkpoint digest over fields 0 through 10.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecomputeCheckpointV1 {
    pub plan_digest: [u8; 32],
    pub tick: u64,
    pub seq: u64,
    pub scheduler_position: u32,
    /// Ordered strictly by owner-identifier bytes; 0 through 4,096 entries.
    pub plugin_state_digests: Vec<CheckpointDigestEntryV1>,
    /// Ordered strictly by owner-identifier bytes; 0 through 4,096 entries.
    pub projection_digests: Vec<CheckpointDigestEntryV1>,
    /// Ordered strictly by owner-identifier bytes; 1 through 4,096 entries.
    pub state_digests: Vec<CheckpointDigestEntryV1>,
    pub exogenous_cursor: ExogenousCursorV1,
    pub provenance_root: [u8; 32],
    pub checkpoint_digest: [u8; 32],
}

impl RecomputeCheckpointV1 {
    /// Validate the closed RCP1 contract and its declared checkpoint digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, or digest is invalid.
    pub fn validate(&self) -> Result<(), RecomputeCheckpointContractErrorV1> {
        self.digest().and_then(|expected| {
            if expected == self.checkpoint_digest {
                Ok(())
            } else {
                Err(RecomputeCheckpointContractErrorV1::DigestMismatch)
            }
        })
    }

    /// Encode this checkpoint as an exact deterministic-CBOR RCP1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, RecomputeCheckpointContractErrorV1> {
        self.validate().and_then(|()| {
            let mut fields = checkpoint_fields(self);
            fields.push(bytes_value(&self.checkpoint_digest));
            encode_value(&Value::Array(fields)).map_err(contract_error)
        })
    }

    /// Decode and validate exact canonical RCP1 bytes.
    ///
    /// The encoded-size limit is checked before any CBOR value is allocated.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// invalid RCP1 records, including a mismatched checkpoint digest.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, RecomputeCheckpointContractErrorV1> {
        decode_canonical(bytes, LIMITS)
            .map_err(contract_error)
            .and_then(|value| decode_checkpoint(&value))
            .and_then(|checkpoint| checkpoint.validate().map(|()| checkpoint))
    }

    /// Compute the RCP1 digest over fields 0 through 10 using the
    /// `PiglorOS.RecomputeCheckpoint.v1\0` domain.
    ///
    /// The declared `checkpoint_digest` is not an input, so a producer can
    /// compute it for a structurally valid candidate.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field other than the declared
    /// digest is structurally invalid.
    pub fn digest(&self) -> Result<[u8; 32], RecomputeCheckpointContractErrorV1> {
        validate_structure(self)
            .and_then(|()| {
                encode_value(&Value::Array(checkpoint_fields(self))).map_err(contract_error)
            })
            .map(|unsigned| domain_digest(DIGEST_DOMAIN, &unsigned))
    }
}

fn validate_structure(
    checkpoint: &RecomputeCheckpointV1,
) -> Result<(), RecomputeCheckpointContractErrorV1> {
    if checkpoint.plan_digest == ZERO_DIGEST || checkpoint.provenance_root == ZERO_DIGEST {
        return Err(RecomputeCheckpointContractErrorV1::FieldOutOfBounds);
    }
    validate_entries(&checkpoint.plugin_state_digests, 0)
        .and_then(|()| validate_entries(&checkpoint.projection_digests, 0))
        .and_then(|()| validate_entries(&checkpoint.state_digests, 1))
        .and_then(|()| validate_cursor(&checkpoint.exogenous_cursor))
}

fn validate_entries(
    entries: &[CheckpointDigestEntryV1],
    minimum: usize,
) -> Result<(), RecomputeCheckpointContractErrorV1> {
    if entries.len() < minimum
        || entries.len() > MAX_CHECKPOINT_DIGEST_ENTRIES_V1
        || !entries.iter().all(valid_entry)
    {
        return Err(RecomputeCheckpointContractErrorV1::FieldOutOfBounds);
    }
    entries.windows(2).try_for_each(|pair| {
        match pair[0].owner_id.as_bytes().cmp(pair[1].owner_id.as_bytes()) {
            Ordering::Less => Ok(()),
            Ordering::Equal => Err(RecomputeCheckpointContractErrorV1::DuplicateIdentity),
            Ordering::Greater => Err(RecomputeCheckpointContractErrorV1::NonCanonicalOrder),
        }
    })
}

fn valid_entry(entry: &CheckpointDigestEntryV1) -> bool {
    !entry.owner_id.is_empty()
        && entry.owner_id.len() <= MAX_CHECKPOINT_OWNER_ID_BYTES_V1
        && entry.digest != ZERO_DIGEST
}

fn validate_cursor(cursor: &ExogenousCursorV1) -> Result<(), RecomputeCheckpointContractErrorV1> {
    let consistent = cursor
        .last_descriptor_digest
        .map_or(cursor.consumed_descriptors == 0, |digest| {
            cursor.consumed_descriptors != 0 && digest != ZERO_DIGEST
        });
    if consistent && cursor.consumed_descriptors <= MAX_EXOGENOUS_CURSOR_POSITION_V1 {
        Ok(())
    } else {
        Err(RecomputeCheckpointContractErrorV1::FieldOutOfBounds)
    }
}

fn checkpoint_fields(checkpoint: &RecomputeCheckpointV1) -> Vec<Value> {
    vec![
        text_value(RECOMPUTE_CHECKPOINT_MAGIC_V1),
        uint_value(1),
        bytes_value(&checkpoint.plan_digest),
        uint_value(checkpoint.tick),
        uint_value(checkpoint.seq),
        uint_value(checkpoint.scheduler_position.into()),
        encode_entries(&checkpoint.plugin_state_digests),
        encode_entries(&checkpoint.projection_digests),
        encode_entries(&checkpoint.state_digests),
        Value::Array(vec![
            uint_value(checkpoint.exogenous_cursor.consumed_descriptors),
            checkpoint
                .exogenous_cursor
                .last_descriptor_digest
                .as_ref()
                .map_or(Value::Null, |digest| bytes_value(digest.as_slice())),
        ]),
        bytes_value(&checkpoint.provenance_root),
    ]
}

fn encode_entries(entries: &[CheckpointDigestEntryV1]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                Value::Array(vec![
                    text_value(&entry.owner_id),
                    bytes_value(&entry.digest),
                ])
            })
            .collect(),
    )
}

fn decode_checkpoint(
    value: &Value,
) -> Result<RecomputeCheckpointV1, RecomputeCheckpointContractErrorV1> {
    let mut fields = FieldReader::with_header(value, FIELD_COUNT, RECOMPUTE_CHECKPOINT_MAGIC_V1, 1);
    let plan_digest = fields.read_bytes::<32>();
    let tick = fields.read_u64();
    let seq = fields.read_u64();
    let scheduler_position = fields.read_u32();
    let plugin_state_digests = fields.read_array(entry_field);
    let projection_digests = fields.read_array(entry_field);
    let state_digests = fields.read_array(entry_field);
    let exogenous_cursor = fields.read_with(
        cursor_field,
        ExogenousCursorV1 {
            consumed_descriptors: 0,
            last_descriptor_digest: None,
        },
    );
    let provenance_root = fields.read_bytes::<32>();
    let checkpoint_digest = fields.read_bytes::<32>();
    fields
        .finish()
        .map(|()| RecomputeCheckpointV1 {
            plan_digest,
            tick,
            seq,
            scheduler_position,
            plugin_state_digests,
            projection_digests,
            state_digests,
            exogenous_cursor,
            provenance_root,
            checkpoint_digest,
        })
        .map_err(contract_error)
}

fn entry_field(value: &Value) -> Result<CheckpointDigestEntryV1, WireError> {
    let mut fields = FieldReader::new(value, 2);
    let owner_id = fields.read_text();
    let digest = fields.read_bytes::<32>();
    fields
        .finish()
        .map(|()| CheckpointDigestEntryV1 { owner_id, digest })
}

fn cursor_field(value: &Value) -> Result<ExogenousCursorV1, WireError> {
    let mut fields = FieldReader::new(value, 2);
    let consumed_descriptors = fields.read_u64();
    let last_descriptor_digest = fields.read_optional_bytes::<32>();
    fields.finish().map(|()| ExogenousCursorV1 {
        consumed_descriptors,
        last_descriptor_digest,
    })
}

const fn contract_error(error: WireError) -> RecomputeCheckpointContractErrorV1 {
    match error {
        // RCP1 has no enum field, so the reader never reports an unknown code.
        WireError::InvalidEncoding | WireError::UnknownEnum => {
            RecomputeCheckpointContractErrorV1::InvalidEncoding
        }
        WireError::FieldOutOfBounds => RecomputeCheckpointContractErrorV1::FieldOutOfBounds,
        WireError::UnsupportedVersion => RecomputeCheckpointContractErrorV1::UnsupportedVersion,
    }
}
