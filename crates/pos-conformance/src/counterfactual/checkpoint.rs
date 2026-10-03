//! Immutable RCP1 recompute checkpoints defined by ADR-064.
//!
//! A `RecomputeCheckpointV1` binds one deterministic counterfactual suffix
//! recomputation coordinate to the exact Plugin, Projection, and state digests
//! that were committed at that coordinate. This module owns only the strict
//! codec, the domain-separated digest, and structural validation; checkpoint
//! persistence, eviction, state serialization, Tick execution, and recovery
//! belong to the core `CounterfactualCoordinator`.

use crate::domain_digest;
use ciborium::value::Value;
use std::cmp::Ordering;
use std::io::Cursor;

/// Magic for the immutable recompute-checkpoint record.
pub const RECOMPUTE_CHECKPOINT_MAGIC_V1: &str = "RCP1";
/// Maximum encoded size of an RCP1 recompute checkpoint.
pub const MAX_RECOMPUTE_CHECKPOINT_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of entries in each ordered RCP1 digest list.
pub const MAX_CHECKPOINT_DIGEST_ENTRIES_V1: usize = 4_096;
/// Maximum encoded byte length of one RCP1 owner identifier.
pub const MAX_CHECKPOINT_OWNER_ID_BYTES_V1: usize = 128;
/// Maximum exogenous cursor position; a plan freezes at most 65,536 descriptors.
pub const MAX_EXOGENOUS_CURSOR_POSITION_V1: u64 = 65_536;

const FIELD_COUNT: usize = 12;
const DIGEST_DOMAIN: &[u8] = b"PiglorOS.RecomputeCheckpoint.v1";
const MAX_NESTING_DEPTH: u8 = 3;
const MAX_NESTED_ARRAY_ITEMS: u64 = MAX_CHECKPOINT_DIGEST_ENTRIES_V1 as u64;
const ZERO_DIGEST: [u8; 32] = [0; 32];

// A structurally valid RCP1 record encodes to at most about 2 MiB (three lists of
// 4,096 entries of at most 165 bytes each plus fixed fields), so the 16 MiB limit
// is enforced on untrusted input before allocation rather than after encoding.

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
        encode_validated_checkpoint(self).map(|_| ())
    }

    /// Encode this checkpoint as an exact deterministic-CBOR RCP1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or canonical encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, RecomputeCheckpointContractErrorV1> {
        encode_validated_checkpoint(self)
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
        if bytes.len() > MAX_RECOMPUTE_CHECKPOINT_BYTES_V1 {
            Err(RecomputeCheckpointContractErrorV1::FieldOutOfBounds)
        } else {
            decode_value(bytes)
                .and_then(|value| decode_checkpoint(&value))
                .and_then(|checkpoint| checkpoint.validate().map(|()| checkpoint))
        }
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
            .and_then(|()| encode_value(&Value::Array(checkpoint_fields(self))))
            .map(|unsigned| domain_digest(DIGEST_DOMAIN, &unsigned))
    }
}

fn encode_validated_checkpoint(
    checkpoint: &RecomputeCheckpointV1,
) -> Result<Vec<u8>, RecomputeCheckpointContractErrorV1> {
    checkpoint.digest().and_then(|expected| {
        if expected == checkpoint.checkpoint_digest {
            let mut fields = checkpoint_fields(checkpoint);
            fields.push(digest_bytes(&checkpoint.checkpoint_digest));
            encode_value(&Value::Array(fields))
        } else {
            Err(RecomputeCheckpointContractErrorV1::DigestMismatch)
        }
    })
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
        Value::Text(RECOMPUTE_CHECKPOINT_MAGIC_V1.to_owned()),
        uint(1),
        digest_bytes(&checkpoint.plan_digest),
        uint(checkpoint.tick),
        uint(checkpoint.seq),
        uint(u64::from(checkpoint.scheduler_position)),
        encode_entries(&checkpoint.plugin_state_digests),
        encode_entries(&checkpoint.projection_digests),
        encode_entries(&checkpoint.state_digests),
        Value::Array(vec![
            uint(checkpoint.exogenous_cursor.consumed_descriptors),
            checkpoint
                .exogenous_cursor
                .last_descriptor_digest
                .as_ref()
                .map_or(Value::Null, digest_bytes),
        ]),
        digest_bytes(&checkpoint.provenance_root),
    ]
}

fn encode_entries(entries: &[CheckpointDigestEntryV1]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                Value::Array(vec![
                    Value::Text(entry.owner_id.clone()),
                    digest_bytes(&entry.digest),
                ])
            })
            .collect(),
    )
}

fn decode_checkpoint(
    value: &Value,
) -> Result<RecomputeCheckpointV1, RecomputeCheckpointContractErrorV1> {
    let fields = array(value, FIELD_COUNT)?;
    decode_header(&fields[0], &fields[1])?;
    Ok(RecomputeCheckpointV1 {
        plan_digest: digest_value(&fields[2])?,
        tick: uint_value(&fields[3])?,
        seq: uint_value(&fields[4])?,
        scheduler_position: scheduler_position_value(&fields[5])?,
        plugin_state_digests: entries_value(&fields[6])?,
        projection_digests: entries_value(&fields[7])?,
        state_digests: entries_value(&fields[8])?,
        exogenous_cursor: cursor_value(&fields[9])?,
        provenance_root: digest_value(&fields[10])?,
        checkpoint_digest: digest_value(&fields[11])?,
    })
}

fn decode_header(magic: &Value, version: &Value) -> Result<(), RecomputeCheckpointContractErrorV1> {
    let magic = text_value(magic)?;
    let version = uint_value(version)?;
    if magic == RECOMPUTE_CHECKPOINT_MAGIC_V1 && version == 1 {
        Ok(())
    } else {
        Err(RecomputeCheckpointContractErrorV1::UnsupportedVersion)
    }
}

fn scheduler_position_value(value: &Value) -> Result<u32, RecomputeCheckpointContractErrorV1> {
    uint_value(value).and_then(|position| {
        u32::try_from(position).map_err(|_| RecomputeCheckpointContractErrorV1::FieldOutOfBounds)
    })
}

fn entries_value(
    value: &Value,
) -> Result<Vec<CheckpointDigestEntryV1>, RecomputeCheckpointContractErrorV1> {
    match value {
        Value::Array(values) => values.iter().map(entry_value).collect(),
        _ => Err(RecomputeCheckpointContractErrorV1::InvalidEncoding),
    }
}

fn entry_value(
    value: &Value,
) -> Result<CheckpointDigestEntryV1, RecomputeCheckpointContractErrorV1> {
    let fields = array(value, 2)?;
    Ok(CheckpointDigestEntryV1 {
        owner_id: text_value(&fields[0])?,
        digest: digest_value(&fields[1])?,
    })
}

fn cursor_value(value: &Value) -> Result<ExogenousCursorV1, RecomputeCheckpointContractErrorV1> {
    let fields = array(value, 2)?;
    Ok(ExogenousCursorV1 {
        consumed_descriptors: uint_value(&fields[0])?,
        last_descriptor_digest: match &fields[1] {
            Value::Null => None,
            digest => Some(digest_value(digest)?),
        },
    })
}

fn encode_value(value: &Value) -> Result<Vec<u8>, RecomputeCheckpointContractErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| RecomputeCheckpointContractErrorV1::InvalidEncoding)
}

fn decode_value(bytes: &[u8]) -> Result<Value, RecomputeCheckpointContractErrorV1> {
    preflight_cbor(bytes).and_then(|()| {
        ciborium::from_reader(Cursor::new(bytes))
            .map_err(|_| RecomputeCheckpointContractErrorV1::InvalidEncoding)
            .and_then(|value| {
                encode_value(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(RecomputeCheckpointContractErrorV1::InvalidEncoding)
                    }
                })
            })
    })
}

fn preflight_cbor(bytes: &[u8]) -> Result<(), RecomputeCheckpointContractErrorV1> {
    crate::preflight_array_cbor(bytes, MAX_NESTING_DEPTH, MAX_NESTED_ARRAY_ITEMS, true).map_err(
        |error| match error {
            crate::CborPreflightError::InvalidEncoding => {
                RecomputeCheckpointContractErrorV1::InvalidEncoding
            }
            crate::CborPreflightError::FieldOutOfBounds => {
                RecomputeCheckpointContractErrorV1::FieldOutOfBounds
            }
        },
    )
}

fn array(value: &Value, length: usize) -> Result<&[Value], RecomputeCheckpointContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(RecomputeCheckpointContractErrorV1::InvalidEncoding),
    }
}

fn text_value(value: &Value) -> Result<String, RecomputeCheckpointContractErrorV1> {
    match value {
        Value::Text(value) => Ok(value.clone()),
        _ => Err(RecomputeCheckpointContractErrorV1::InvalidEncoding),
    }
}

fn uint_value(value: &Value) -> Result<u64, RecomputeCheckpointContractErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| RecomputeCheckpointContractErrorV1::InvalidEncoding)
        }
        _ => Err(RecomputeCheckpointContractErrorV1::InvalidEncoding),
    }
}

fn digest_value(value: &Value) -> Result<[u8; 32], RecomputeCheckpointContractErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| RecomputeCheckpointContractErrorV1::InvalidEncoding),
        _ => Err(RecomputeCheckpointContractErrorV1::InvalidEncoding),
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn digest_bytes(value: &[u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}
